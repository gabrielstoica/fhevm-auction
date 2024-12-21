// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import { SepoliaZamaFHEVMConfig } from "fhevm/config/ZamaFHEVMConfig.sol";
import { IConfidentialERC20 } from "fhevm-contracts/contracts/token/ERC20/IConfidentialERC20.sol";

contract EncryptedSinglePriceAuction is SepoliaZamaFHEVMConfig {
    /// @dev The address of the native token (ETH) following the EIP-7528 standard
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /*//////////////////////////////////////////////////////////////////////////
                                    PUBLIC STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Struct encapsulating the different values describing an auction
    /// @param startTime The start time of the auction
    /// @param endTime The end time of the auction
    /// @param creator The address of the auction creator
    /// @param assetToken The address of the asset token being auctioned
    /// @param assetAmount The amount of the asset token being auctioned
    /// @param paymentToken The token contract used for encrypted bids (can be the native token or a ERC20 token)
    /// @param settled Whether the auction has been settled
    struct Auction {
        uint40 startTime;
        uint40 endTime;
        address creator;
        address assetToken;
        uint256 assetAmount;
        address paymentToken;
        bool settled;
    }

    /// @notice Struct encapsulating the different values describing a bid
    /// @param at The timestamp at which the bid was placed
    /// @param amount The amount of the bid
    /// @param pricePerToken The price per token
    struct Bid {
        uint40 at;
        euint64 amount;
        euint64 pricePerToken;
    }

    /// @notice Mapping storing the different auctions by their ID
    mapping(uint256 auctionId => Auction) public auctions;

    /// @notice Mapping storing the different bids for each auction by the bidder's address
    mapping(uint256 auctionId => mapping(address bidder => Bid)) public bids;

    /*//////////////////////////////////////////////////////////////////////////
                                    PRIVATE STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice The next auction ID
    uint256 private _nextAuctionId;

    /*//////////////////////////////////////////////////////////////////////////
                                       EVENTS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new auction is created
    /// @param auctionId The ID of the auction
    /// @param creator The address of the auction creator
    /// @param assetToken The address of the asset token being auctioned
    /// @param assetAmount The amount of the asset token being auctioned
    /// @param paymentToken The token contract used for encrypted bids (can be the native token or a ERC20 token)
    event AuctionCreated(
        uint256 indexed auctionId,
        address indexed creator,
        address indexed assetToken,
        uint256 assetAmount,
        address paymentToken
    );

    /*//////////////////////////////////////////////////////////////////////////
                                       ERRORS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the auction is not active (not started or already ended)
    error AuctionNotActive();

    /*//////////////////////////////////////////////////////////////////////////
                                CONTRACT-SPECIFIC FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Creates a new auction
    /// @param startTime The start time of the auction
    /// @param endTime The end time of the auction
    /// @param assetToken The address of the asset token being auctioned
    /// @param assetAmount The amount of the asset token being auctioned
    /// @param paymentToken The token contract used for encrypted bids (can be the native token or a ERC20 token)
    function createAuction(
        uint40 startTime,
        uint40 endTime,
        address assetToken,
        uint256 assetAmount,
        address paymentToken
    ) external {
        // Get the next auction ID
        uint256 auctionId = _nextAuctionId;

        // Effects: create the auction
        auctions[auctionId] = Auction({
            startTime: startTime,
            endTime: endTime,
            creator: msg.sender,
            assetToken: assetToken,
            assetAmount: assetAmount,
            paymentToken: paymentToken,
            settled: false
        });

        // Effects: increment the next auction ID
        // Using unchecked because the auction ID cannot realistically overflow
        unchecked {
            _nextAuctionId++;
        }

        // Log the auction creation
        emit AuctionCreated(auctionId, msg.sender, assetToken, assetAmount, paymentToken);
    }

    /// @notice Places a bid for a given auction
    /// @param auctionId The ID of the auction
    /// @param encryptedAmount The encrypted amount of the bid
    /// @param encryptedPricePerToken The encrypted price per token
    /// @param inputProof The zero-knowledge proof of knowledge (ZKPoK) for the encrypted bid amount and price per token
    function placeBid(
        uint256 auctionId,
        einput encryptedAmount,
        einput encryptedPricePerToken,
        bytes calldata inputProof
    ) external payable {
        // Retrieve the auction from storage
        Auction memory auction = auctions[auctionId];

        // Checks: the auction is active
        if (block.timestamp < auction.startTime || block.timestamp > auction.endTime) {
            revert AuctionNotActive();
        }

        // Validate and convert the encrypted bid amount and price per token
        // against the associated `inputProof` zero-knowledge proof of knowledge
        // Note: we need the ZKPoK to ensure the validity of the encrypted data without revealing the plaintext
        euint64 amount = TFHE.asEuint64(encryptedAmount, inputProof);
        euint64 pricePerToken = TFHE.asEuint64(encryptedPricePerToken, inputProof);

        // Compute the total price that must be paid by the bidder by multiplying the amount by the price per token
        euint64 totalPrice = TFHE.mul(amount, pricePerToken);

        // Retrieve the bid from storage to check if the user has already placed one
        Bid memory existingBid = bids[auctionId][msg.sender];

        // Checks: the user has already placed a bid
        if (TFHE.isInitialized(existingBid.amount)) {
            // Compute the total price of the existing bid
            euint64 currentTotalPrice = TFHE.mul(existingBid.amount, existingBid.pricePerToken);

            // Checks: the payment token is whether in the native token or a ERC20 token
            if (auction.paymentToken == NATIVE_TOKEN) {} else {
                // Check if the new bid is higher than the existing one
                // This can occur due to either:
                // - The new bid amount is higher than the current amount
                // - The new bid price per token is higher than the current price per token
                ebool isHigher = TFHE.lt(currentTotalPrice, totalPrice);

                // Compute the amount to transfer representing the difference between the new bid and the existing one
                // Note:
                // - We presume the new bid is higher than the existing bid
                // - Otherwise, the subtraction can underflow if the bid amount is smaller than the existing bid amount
                euint64 toTransfer = TFHE.sub(totalPrice, currentTotalPrice);

                // To prevent underflow, we transfer the `toTransfer` amount only if the new bid is higher than the existing one
                // otherwise we're not transferring anything (amount will be encrypted 0)
                toTransfer = TFHE.select(isHigher, toTransfer, TFHE.asEuint64(0));

                // Grant temporary access for the duration of this transaction to the auction's `paymentToken`
                // to operate with the `amount` amount
                TFHE.allowTransient(amount, address(auction.paymentToken));

                // Effects: update the bid
                bids[auctionId][msg.sender] = Bid({
                    at: uint40(block.timestamp),
                    amount: TFHE.add(existingBid.amount, toTransfer),
                    pricePerToken: pricePerToken
                });

                // Interactions: transfer the tokens to this contract which is acting as a vault
                IConfidentialERC20(auction.paymentToken).transferFrom(msg.sender, address(this), toTransfer);
            }
        } else {
            // Checks: the payment token is whether in the native token or a ERC20 token
            if (auction.paymentToken == NATIVE_TOKEN) {} else {}

            // Effects: place the bid
            bids[auctionId][msg.sender] = Bid({
                at: uint40(block.timestamp),
                amount: amount,
                pricePerToken: pricePerToken
            });
        }
    }
}

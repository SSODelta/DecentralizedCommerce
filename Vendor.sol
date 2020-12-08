// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.7.0;

/// @title An Incentive-Compatible Smart Contract for Decentralized Commerce
/// @notice This contract can be used by two mutually distrusting parties to transact any physical good or service with provably game-theoretic security. This implementation uses the coin-flip arbiter.
/// @author Nikolaj I. Schwartzbach
contract Vendor {
    
    // Address of the vendor.
    address payable seller;
    
    // Public key of the seller (PGP or similar).
    string public publicKey;
    
    /// Timeout (in sec.)
    uint public timeout;
    
    /// @notice Create a new Vendor contract.
    /// @param _timeout The timeout (in seconds).
    /// @param _publicKey Public key of the vendor (PGP or similar).
    constructor(uint _timeout, string memory _publicKey) {
        require(_timeout > 0);      // Must have strictly positive timeout.
        seller = msg.sender;        // Store seller address.
        timeout = _timeout;         // Store timeout (in sec.).
        publicKey = _publicKey;     // Store public key.
    }
    
    /// The states of the contract.
    enum State { Null, Requested, Accepted, Rejected, Delivered, Completed, Dispute, Counter, Failed }
    
    /// A vendor item.
    struct Item {
        uint itemValue;         // Value of item (in wei).
        string itemDescription; // Description of item (optional).
    }
    
    /// A single purchase by a buyer.
    struct Purchase {
        bytes32 commit;         // Commitment to buyer random bit
        uint lastBlock;         // The last block where activity was recorded (for timeouts).
        uint item;              // Identifier of the item purchased.
        bool sellerBit;         // Seller random bit
        
        string notes;           // Buyer notes about purchase (shipping etc.)
        State state;            // Current state of the purchase.
        
        address payable buyer;  // Address of the buyer
    }
    
    /// All contracts of this vendor.
    mapping (bytes32 => Purchase) public contracts;
    
    /// All listings by this vendor.
    mapping (uint => Item) public listings;
    
    // BUYER FUNCTIONS
    
    /// @notice Request purchase of item from vendor.
    /// @param _item Identifier of the item.
    /// @param _notes Information about the purchase (shipping/extra details), possibly encrypted with seller PGP key.
    /// @return hash of the purchase, used to access purchase later.
    function buyer_RequestPurchase(uint _item, string memory _notes) public payable returns(bytes32) {
        require(msg.value == listings[_item].itemValue);    // Must pay the correct amount
        
        // Compute id from timestamp and buyer.
        bytes32 id = keccak256(abi.encodePacked(block.timestamp, msg.sender));
        
        // Create the contract (the expensive part).
        contracts[id] = Purchase({
            item: _item,
            lastBlock: block.timestamp,
            state: State.Requested,
            buyer: msg.sender,
            sellerBit: false,
            commit: 0x0,
            notes: _notes
        });
        
        return id;
    }
    
    
    /// @notice Buyer aborts contract before seller has accepted/rejected it.
    /// @param id Hash of the contract.
    function buyer_Abort(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);                     // Only the buyer can abort the contract.
        require(contracts[id].state ==  State.Requested);               // Can only abort contract before vendor has interacted with contract.
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);            // Return money to buyer.
    }
    
    /// @notice Buyer confirms delivery of item by seller.
    /// @param id Hash of the contract.
    function buyer_ConfirmDelivery(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);                     // Only the buyer can confirm the delivery.
        require(contracts[id].state == State.Delivered);                // Can only confirm delivery after vendor has claimed delivery.
    
        contracts[id].state = State.Completed;
        seller.transfer(address(this).balance);                         // Send payment to seller.
    }
    
    /// @notice Buyer issues a dispute by placing a wager of the same size as the price of the item.
    /// @param id Hash of the contract.
    /// @param commitment Commitment of random bit, i.e. keccak256(bit, id, nonce) where id is hash of contract.
    function buyer_DisputeDelivery(bytes32 id, bytes32 commitment) public payable {
        require(msg.sender == contracts[id].buyer);                     // Only buyer can dispute the delivery.
        require(contracts[id].state == State.Delivered);                // Can only dispute delivery when vendor has claimed delivery.
        require(listings[contracts[id].item].itemValue == msg.value);   // Has to wager same value as transaction.
        
        contracts[id].state = State.Dispute;
        contracts[id].commit = commitment;                              // Store buyer's commitment to random bit.
        contracts[id].lastBlock = block.timestamp;                      // Store last timestamp (for timeouts).
    }
    
    /// @notice Buyer calls timeout and receives back the money in the contract. Can only be done if timeout seconds has passed without seller action.
    /// @param id Hash of the contract.
    function buyer_CallTimeout(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);                     // Only buyer can call this timeout function.
        require(contracts[id].state == State.Dispute                    // ... if the seller did not respond to their dispute
             || contracts[id].state == State.Accepted);                 // ... or if the seller never claimed delivery.
        require(block.timestamp > contracts[id].lastBlock + timeout);   // Can only call timeout when timeout seconds has passed.
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);            // Transfer funds to buyer.
    }
    
    /// @notice Buyer opens the commitment to reveal their random bit. 
    /// @param id Hash of the contract.
    function buyer_OpenCommitment(bytes32 id, bool _buyerBit, bytes32 nonce) public {
        require(msg.sender == contracts[id].buyer);                                     // Only buyer can open commitment.
        require(contracts[id].state == State.Counter);                                  // Can only open commitment if seller has countered.
        require(contracts[id].commit == keccak256(abi.encodePacked(_buyerBit, id, nonce)));     // Check that (_buyerBit,nonce) is opening of commitment.
        
        contracts[id].state = State.Failed;
        if(contracts[id].sellerBit != _buyerBit){                                   // Flip random coin (use randomness from each party, as [Blum83])
            seller.transfer(2*listings[contracts[id].item].itemValue);               // If heads, pay back seller their deposit and the value of the transaction (2*value)
        } else {
            contracts[id].buyer.transfer(2*listings[contracts[id].item].itemValue);  // If tails, pay back buyer their deposit and value of the transaction (2*value)
        }
    }
    
    // SELLER FUNCTIONS
    
    
    /// @notice Seller calls timeout and receives back the money in the contract. Can only be done if timeout seconds has passed without buyer action.
    /// @param id Hash of the contract.
    function seller_CallTimeout(bytes32 id) public {
        require(msg.sender == seller);                                      // Only seller can call this timeout function.
        require(contracts[id].state == State.Delivered                      // ... if the buyer does not respond to delivery.
             || contracts[id].state == State.Counter);                      // ... or if the buyer does not open their commitment.
        require(block.timestamp > contracts[id].lastBlock + timeout);       // Can only timeout after timeout second.
        
        contracts[id].state = State.Completed;
        seller.transfer(address(this).balance);                             // Transfer all funds to the seller.
    }
    
    /// @notice Seller rejects the purchase of the buyer.
    /// @param id Hash of the contract.
    function seller_RejectContract(bytes32 id) public {
        require(msg.sender == seller);                                      // Only seller can reject the contract.
        require(contracts[id].state == State.Requested);                    // Can only reject contract when buyer has requested.
        
        contracts[id].state = State.Rejected;
        contracts[id].buyer.transfer(address(this).balance);                // Transfer funds back to buyer.
    }
    
    /// @notice Seller accepts the purchase of the buyer.
    /// @param id Hash of the contract.
    function seller_AcceptContract(bytes32 id) public {
        require(msg.sender == seller);                                      // Only seller can accept the contract.
        require(contracts[id].state == State.Requested);                    // Can only accept contract when buyer has requested.
        
        contracts[id].state = State.Accepted;
        contracts[id].lastBlock = block.timestamp;                          // Store last timestamp to allow buyer to call timeout.
    }
    
    /// @notice Seller notifies the buyer that the item was delivered.
    /// @param id Hash of the contract.
    function seller_ItemWasDelivered(bytes32 id) public {
        require(msg.sender == seller);                                      // Only seller can confirm item was delivered.
        require(contracts[id].state == State.Accepted);                     // Can only claim delivery of item after it is accepted.
        
        contracts[id].state = State.Delivered;
        contracts[id].lastBlock = block.timestamp;                          // Store last timestamp to allow seller to call timeout.
    }
    
    /// @notice Seller forfeits the dispute of the buyer and returns back the money to the buyer.
    /// @param id Hash of the contract.
    function seller_ForfeitDispute(bytes32 id) public {
        require(msg.sender == seller);                                      // Only seller can forfeit the dispute of the buyer.
        require(contracts[id].state == State.Dispute);                      // Can only forfeit dispute if buyer disputed delivery.
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);                // Transfer funds to buyer.
    }
    
    /// @notice Seller counters the dispute of the buyer by also placing a wager of the same size as the price of the item.
    /// @param id Hash of the contract.
    function seller_CounterDispute(bytes32 id, bool randomBit) public payable {
        require(msg.sender == seller);                                      // Only seller can counter dispute.
        require(contracts[id].state == State.Dispute);                      // Can only counter dispute if buyer disputed delivery.
        require(msg.value == listings[contracts[id].item].itemValue);       // Seller has to wager the value of the item.
        
        contracts[id].state = State.Counter;
        contracts[id].lastBlock = block.timestamp;                          // Store timestamp to allow seller to call timeout if buyer does not open commitment.
        contracts[id].sellerBit = randomBit;                                // Store seller random bit.
    }
    
    /// @notice Seller updates the information about a listing.
    /// @param itemId id of the item to update.
    /// @param descr Description of the item.
    /// @param value The price of the item (in gwei).
    function seller_UpdateListings(uint itemId, string memory descr, uint value) public {
        require(msg.sender == seller);                  // Only seller can update listings.
        
        listings[itemId].itemValue = value*(10**9);     // Multiply by 10^9 to get gwei in wei.
        listings[itemId].itemDescription = descr;       // Update description of item.
    }
    
    /// @notice Only used for testing purposes. Do NOT use this to make actual commitments.
    /// @param bit The bit to commit to.
    /// @param id The hash of the contract.
    /// @param nonce The nonce used for the commitment.
    function testKeccak(bool bit, bytes32 id, bytes32 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bit, id, nonce));
    }
    
}

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
    uint40 public timeout;
    
    /// @notice Create a new Vendor contract.
    /// @param _timeout The timeout (in seconds).
    /// @param _publicKey Public key of the vendor (PGP or similar).
    constructor(uint40 _timeout, string memory _publicKey) {
        seller = msg.sender;
        timeout = _timeout;
        publicKey = _publicKey;
    }
    
    /// The states of the contract.
    enum State { Null, Requested, Accepted, Rejected, Delivered, Completed, Dispute, Counter, Failed }
    
    /// A vendor item.
    struct Item {
        uint256 itemValue;
        string itemDescription;
    }
    
    /// A single purchase by a buyer.
    struct Purchase {
        uint256 value;          // Value of the item (in wei)
        uint256 lastBlock;      // The last block where activity was recorded.
        uint16 item;            // Identifier of the item purchased.
        bytes32 commit;         // Commitment to buyer random bit
        bool sellerBit;         // Seller random bit
        bool buyerBit;          // Buyer random bit
        
        string notes;           // Buyer notes about purchase (shipping etc.)
        State state;            // Current state of the purchase.
        
        address payable buyer;  // Address of the buyer
    }
    
    /// All contracts of this vendor.
    mapping (bytes32 => Purchase) public contracts;
    
    /// All listings by this vendor.
    mapping (uint16 => Item) public listings;
    
    // BUYER FUNCTIONS
    
    /// @notice Request purchase of item from vendor.
    /// @param _item Identifier of the item.
    /// @param _notes Information about the purchase (shipping/extra details), possibly encrypted with seller PGP key.
    /// @return hash of the purchase, used to access purchase later.
    function buyer_RequestPurchase(uint16 _item, string memory _notes) public payable returns(bytes32) {
        require(msg.value == listings[_item].itemValue);
        bytes32 id = keccak256(abi.encodePacked(block.timestamp, msg.sender));
        contracts[id] = Purchase({
            value: msg.value,
            item: _item,
            lastBlock: block.timestamp,
            state: State.Requested,
            buyer: msg.sender,
            sellerBit: false,
            buyerBit: true,
            commit: 0x0,
            notes: _notes
        });
        return id;
    }
    
    
    /// @notice Buyer aborts contract before seller has accepted/rejected it.
    /// @param id Hash of the contract.
    function buyer_Abort(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);
        require(contracts[id].state ==  State.Requested);
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);
    }
    
    /// @notice Buyer confirms delivery of item by seller.
    /// @param id Hash of the contract.
    function buyer_ConfirmDelivery(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);
        require(contracts[id].state == State.Delivered);
    
        contracts[id].state = State.Completed;
        seller.transfer(address(this).balance);
    }
    
    /// @notice Buyer issues a dispute by placing a wager of the same size as the price of the item.
    /// @param id Hash of the contract.
    /// @param commitment Commitment of random bit, i.e. keccak256(bit, id, nonce) where id is hash of contract.
    function buyer_DisputeDelivery(bytes32 id, bytes32 commitment) public payable {
        require(msg.sender == contracts[id].buyer);
        require(contracts[id].state == State.Delivered);
        require(contracts[id].value == msg.value);
        
        contracts[id].state = State.Dispute;
        contracts[id].commit = commitment;
        contracts[id].lastBlock = block.timestamp;
    }
    
    /// @notice Buyer calls timeout and receives back the money in the contract. Can only be done if timeout seconds has passed without seller action.
    /// @param id Hash of the contract.
    function buyer_CallTimeout(bytes32 id) public {
        require(msg.sender == contracts[id].buyer);
        require(contracts[id].state == State.Dispute || contracts[id].state == State.Accepted);
        require(block.timestamp > contracts[id].lastBlock + timeout);
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);
    }
    
    /// @notice Buyer opens the commitment to reveal their random bit. 
    /// @param id Hash of the contract.
    function buyer_OpenCommitment(bytes32 id, bool _buyerBit, bytes32 nonce) public {
        require(msg.sender == contracts[id].buyer);
        require(contracts[id].state == State.Counter);
        require(contracts[id].commit == keccak256(abi.encodePacked(_buyerBit, id, nonce)));
        
        contracts[id].state = State.Failed;
        if(contracts[id].sellerBit != contracts[id].buyerBit){
            seller.transfer(2*contracts[id].value);
        } else {
            contracts[id].buyer.transfer(2*contracts[id].value);
        }
    }
    
    // SELLER FUNCTIONS
    
    
    /// @notice Seller calls timeout and receives back the money in the contract. Can only be done if timeout seconds has passed without buyer action.
    /// @param id Hash of the contract.
    function seller_CallTimeout(bytes32 id) public {
        require(msg.sender == seller);
        require(contracts[id].state == State.Delivered || contracts[id].state == State.Counter);
        require(block.timestamp > contracts[id].lastBlock + timeout);
        
        contracts[id].state = State.Completed;
        contracts[id].buyer.transfer(address(this).balance);
    }
    
    /// @notice Seller rejects the purchase of the buyer.
    /// @param id Hash of the contract.
    function seller_RejectContract(bytes32 id) public {
        require(msg.sender == seller);
        require(contracts[id].state == State.Requested);
        
        contracts[id].state = State.Rejected;
        contracts[id].buyer.transfer(address(this).balance);
    }
    
    /// @notice Seller accepts the purchase of the buyer.
    /// @param id Hash of the contract.
    function seller_AcceptContract(bytes32 id) public {
        require(msg.sender == seller);
        require(contracts[id].state == State.Requested);
        
        contracts[id].state = State.Accepted;
        contracts[id].lastBlock = block.timestamp;
    }
    
    /// @notice Seller notifies the buyer that the item was delivered.
    /// @param id Hash of the contract.
    function seller_ItemWasDelivered(bytes32 id) public {
        require(msg.sender == seller);
        require(contracts[id].state == State.Accepted);
        
        contracts[id].state = State.Delivered;
        contracts[id].lastBlock = block.timestamp;
    }
    
    /// @notice Seller forfeits the dispute of the buyer and returns back the money to the buyer.
    /// @param id Hash of the contract.
    function seller_ForfeitDispute(bytes32 id) public {
        require(msg.sender == seller);
        require(contracts[id].state == State.Dispute);
        
        contracts[id].state = State.Failed;
        contracts[id].buyer.transfer(address(this).balance);
    }
    
    /// @notice Seller counters the dispute of the buyer by also placing a wager of the same size as the price of the item.
    /// @param id Hash of the contract.
    function seller_CounterDispute(bytes32 id, bool randomBit) public payable {
        require(msg.sender == seller);
        require(contracts[id].state == State.Dispute);
        require(msg.value == contracts[id].value);
        
        contracts[id].state = State.Counter;
        contracts[id].lastBlock = block.timestamp;
        contracts[id].sellerBit = randomBit;
    }
    
    /// @notice Seller updates the information about a listing.
    /// @param itemId id of the item to update.
    /// @param descr Description of the item.
    /// @param value The price of the item (in gwei).
    function seller_UpdateListings(uint16 itemId, string memory descr, uint256 value) public {
        require(msg.sender == seller);
        
        listings[itemId].itemValue = value*(10**9);
        listings[itemId].itemDescription = descr;
    }
    
    /// @notice Only used for testing purposes. Do NOT use this to make actual commitments.
    /// @param bit The bit to commit to.
    /// @param id The hash of the contract.
    /// @param nonce The nonce used for the commitment.
    function testKeccak(bool bit, bytes32 id, bytes32 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bit, id, nonce));
    }
    
}

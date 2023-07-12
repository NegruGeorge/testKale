// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "erc721a/contracts/ERC721A.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "operator-filter-registry/src/DefaultOperatorFilterer.sol";

 /**
  * @title NFTPass
  * @dev The contract allows users to mint max 2 NFTs per address.
  * @dev The contract has 2 phases, whitelist sale and public sale.
  * @dev The contract uses a Merkle proof to validate that an address is whitelisted.
  * @dev Each phase lasts one day.
  * @dev Whitelist phase starts on 07.02.2023 at 4 pm UTC, ends in 08.02.2023 at 4 pm UTC.
  * @dev Public phase starts on 08.02.2023 at 4:01 pm UTC, ends in 09.02.2023 at 4 pm UTC.
  * @dev The contract also has an owner who have the privilages to set the state of the contract and withdraw erc20 native tokens.
  */
contract NFTPass is ERC721A, Ownable, ReentrancyGuard, DefaultOperatorFilterer {
    using Strings for uint256;

    /** 
     * @dev Set max supply for the NFTPass collection
     */
    uint256 public constant maxSupply = 2222;

    /** 
     * @dev Set max amount of NFTs per address
     */
    uint256 public constant maxMintPerWallet = 2;

    /** 
     * @dev Set cost for second NFT minted during the whitelist sale period
     */
    uint256 public constant priceWhitelistSale = 0.0035 ether;

    /** 
     * @dev Set cost for second NFT minted during the public sale period
     */
    uint256 public constant pricePublicSale = 0.0035 ether;



    /** 
     * @dev A boolean that indicates whether the mintWhitelistSale function is paused or not.
     */
    bool public pauseWLSale = true;

    /** 
     * @dev A boolean that indicates whether the mintPublicSale function is paused or not.
     */
    bool public pausePBSale = true;


    /** 
     * @dev A boolean that indicates whether the contract isindicates is paused or not.
     */
    bool public globalPause = false;

    /**
     * @dev The root of the Merkle tree that is used for whitelist check.
     */
    bytes32 public merkleRoot;

    /**
     * @dev The account that recive the money from the mints.
     */
    address public payerAccount;

    /** 
     * @dev Prefix for tokens metadata URIs
     */
    string public baseURI;

    /** 
     * @dev Sufix for tokens metadata URIs
     */
    string public uriSuffix = '.json';

    /**
     * @dev A mapping that stores the amount of NFTs minted for each address.
     */
    mapping(address => uint256) public addressMintedAmount;

    /**
     * @dev Emits an event when an NFT is minted in whitelist sale period.
     * @param minterAddress The address of the user who executed the mintWhitelistSale.
     * @param amount The amount of NFTs minted.
     */
    event MintWhitelistSale(
        address indexed minterAddress,
        uint256 amount
    );

    /**
     * @dev Emits an event when an NFT is minted in public sale period.
     * @param minterAddress The address of the user who executed the mintWhitelistSale.
     * @param amount The amount of NFTs minted.
     */
    event MintPublicSale(
        address indexed minterAddress,
        uint256 amount
    );

    /**
     * @dev Emits an event when owner mint a batch.
     * @param owner The addresses who is the contract owner.
     * @param addresses The addresses array.
     * @param amount The amount of NFTs minted for each address.
     */
    event MintBatch(
        address indexed owner,
        address[] addresses,
        uint256 amount
    );
    
    /**
     * @dev Emits an event when owner mint a batch.
     * @param owner The addresses who is the contract owner.
     * @param amount The amount of native tokens withdrawn.
     */
    event Withdraw(
        address indexed owner,
        uint256 amount
    );

    /**
     * @dev Constructor function that sets the initial values for the contract's variables.
     * @param _merkleRoot The root of the Merkle tree.
     * @param uri The metadata URI prefix.
     */
    constructor(
        bytes32 _merkleRoot,
        string  memory uri,
        address _payerAccount
    ) ERC721A("Deviants Silver Mint Pass", "NFPASS") {
        merkleRoot = _merkleRoot;
        baseURI = uri;
        payerAccount = _payerAccount;
    }

     /**
      * @dev mintWhitelistSale creates NFT tokens for whitelist sale.
      * @param _mintAmount the amount of NFT tokens to mint.
      * @param _merkleProof the proof of user's whitelist status.
      * @notice Throws if:
      * - whitelistSale closed if the function is called outside of the whitelist sale period or if the contract is paused.
      * - maxSupply exceeded if the minted amount exceeds the maxSupply.
      * - mintAmount must be 1 or 2 if the _mintAmount is not 1 or 2.
      * - Invalid proof if the provided merkle proof is invalid.
      * - user cannot mint more then 2 NFTs if the user already owns 2 NFTs.
      * - user must send the exact price if the user already owns 1 NFT and tries to mint 2 NFTs.
      */
    function mintWhitelistSale(uint256 _mintAmount, bytes32[] calldata _merkleProof) external payable nonReentrant{
        require(!globalPause,"NFPASS: contract is paused");
        require(totalSupply() + _mintAmount <= maxSupply, "NFPASS: maxSupply exceeded");
        require(_mintAmount == 1 || _mintAmount == 2, "NFPASS: mintAmount must be 1 or 2");
            
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender))));
        require(MerkleProof.verify(_merkleProof, merkleRoot, leaf), "NFPASS: Invalid proof");
        require(_mintAmount + addressMintedAmount[msg.sender] <= 2, "NFPASS: user cannot mint more then 2 NFTs" );
        
        if(addressMintedAmount[msg.sender] == 0 && _mintAmount == 1 ){
            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        }
        else if(addressMintedAmount[msg.sender] == 0 && _mintAmount == 2){
            require(msg.value == priceWhitelistSale,"NFPASS: user must send the exact price");

            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        }
        else{
             require(msg.value == priceWhitelistSale,"NFPASS: user must send the exact price");

            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        } 

        emit MintWhitelistSale(msg.sender, _mintAmount);      
    } 

    /**
     * @dev Mints NFTs in the public sale period.
     * @param _mintAmount The number of NFTs to mint (1 or 2).
     * @notice Throws if:
     * - public sale period has ended or the contract is paused.
     * - The maximum supply of NFTs is exceeded.
     * - The `_mintAmount` is not 1 or 2.
     * - The user tries to mint more than 2 NFTs.
     * - The user tries to mint 2 NFTs but does not send the exact price.
     * - The user tries to mint 1 NFT but sends more than the exact price.
     */
    function mintPublicSale(uint256 _mintAmount) external payable nonReentrant{
        require(!globalPause,"NFPASS: contract is paused");
        require(totalSupply() + _mintAmount <= maxSupply,"NFPASS: maxSupply exceeded");
        require(_mintAmount== 1 || _mintAmount == 2, "NFPASS: mintAmount must be 1 or 2");    
        require(_mintAmount + addressMintedAmount[msg.sender] <= 2,"NFPASS: user cannot mint more then 2 NFTs" );

        if(addressMintedAmount[msg.sender] == 0 && _mintAmount == 1 ){

            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        }
        else if(addressMintedAmount[msg.sender] == 0 && _mintAmount == 2){
            require(msg.value == pricePublicSale,"NFPASS: user must send the exact price");

            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        }
        else{
             require(msg.value == pricePublicSale,"NFPASS: user must send the exact price");
            
            addressMintedAmount[msg.sender] += _mintAmount;
            _safeMint(msg.sender,_mintAmount);
        }    

        emit MintPublicSale(msg.sender, _mintAmount);     
    }

    /**
     * @dev Function to mint a batch of NFTs to multiple addresses
     * @param addresses An array of addresses to mint NFTs to
     * @param _mintAmounts The amount of NFTs to mint to each address
     * @notice Only the contract owner can call this function.
     */
    function mintBatch(address[] memory addresses, uint256 _mintAmounts) external onlyOwner{
        require(totalSupply() + addresses.length * _mintAmounts <= maxSupply,"NFPASS: maxSupply exceeded");

        for(uint256 i = 0;i < addresses.length; i++){
            _safeMint(addresses[i],_mintAmounts);
        }

        emit MintBatch(msg.sender, addresses, _mintAmounts);
    }

    /**
     * @dev Sets the Merkle root on the contract
     * @param _merkleRoot bytes32: the Merkle root to be set
     * @notice Only the contract owner can call this function.
     */
    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner{
        merkleRoot = _merkleRoot;
    }
    
    /**
     * @dev This function sets the base URI of the NFT contract.
     * @param uri The new base URI of the NFT contract.
     * @notice Only the contract owner can call this function.
     */
    function setBasedURI(string memory uri) external onlyOwner{
        baseURI = uri;
    }

    /**
     * @dev Set the pause state of the contract for the WL Sale, only the contract owner can set the pause state
     * @param state Boolean state of the pause, true means that the contract is paused, false means that the contract is not paused
     */
    function setPauseWLSale(bool state) external onlyOwner{
        pauseWLSale = state;
    }

    /**
     * @dev Set the pause state of the contract for the PB Sale, only the contract owner can set the pause state
     * @param state Boolean state of the pause, true means that the contract is paused, false means that the contract is not paused
     */
    function setPausePBSale(bool state) external onlyOwner{
        pausePBSale = state;
    }

    /**
     * @dev Set the global pause state of the contract, only the contract owner can set the pause state
     * @param state Boolean state of the pause, true means that the contract is paused, false means that the contract is not paused
     */
    function setGlobalPause(bool state) external onlyOwner{
        globalPause = state;
    }


    /**
     * @dev Sets the uriSuffix for the ERC-721 token metadata.
     * @param _uriSuffix The new uriSuffix to be set.
     */
    function setUriSuffix(string memory _uriSuffix) public onlyOwner {
        uriSuffix = _uriSuffix;
    }

    /**
     * @dev Sets the payerAccount.
     * @param _payerAccount The new payerAccount.
     */
    function setPayerAccount(address _payerAccount) public onlyOwner {
        payerAccount = _payerAccount;
    }

    /**
     * @dev Returns the state of the WhitelistState (true if is open, false if is closed)
     */
    function getWhitelistSaleStatus() public view returns(bool){
        if(!pauseWLSale) {
            return true;
        }else{
            return false;
        }
    }
    
    /**
     * @dev Returns the state of the PauseSale (true if is open, false if is closed)
     */
    function getPauseSaleStatus() public view returns(bool){
        if(!pausePBSale) {
            return true;
        }else{
            return false;
        }
    }
    
    /**
     * Transfers the total native coin balance to contract's owner account.
     * The balance must be > 0 so a zero transfer is avoided.
     * 
     * Access: Contract Owner
     */
    function withdraw() public nonReentrant {
        require(msg.sender == owner() || msg.sender == payerAccount, "NFPASS: can be called only with the owner or payerAccount");
        uint256 balance = address(this).balance;
        require(balance != 0, "NFPASS: contract balance is zero");
        sendViaCall(payable(payerAccount), balance);

        emit Withdraw(msg.sender, balance);
    }

    /**
     * @dev Function to transfer coins (the native cryptocurrency of the platform, i.e.: ETH) 
     * from this contract to the specified address.
     *
     * @param _to the address to transfer the coins to
     * @param _amount amount (in wei)
     */
    function sendViaCall(address payable _to, uint256 _amount) private {
        (bool sent, ) = _to.call { value: _amount } ("");
        require(sent, "NFPASS: failed to send amount");
    }

    /**
    * @dev Returns the starting token ID for the token.
    * @return uint256 The starting token ID for the token.
    */
    function _startTokenId() internal view virtual override returns (uint256) {
        return 1;
    }

    /**
     * @dev Returns the token URI for the given token ID. Throws if the token ID does not exist
     * @param _tokenId The token ID to retrieve the URI for
     * @notice Retrieve the URI for the given token ID
     * @return The token URI for the given token ID
     */
    function tokenURI(uint256 _tokenId) public view virtual override returns (string memory) {
        require(_exists(_tokenId), 'ERC721Metadata: URI query for nonexistent token');

        string memory currentBaseURI = _baseURI();
        return bytes(currentBaseURI).length > 0
            ? string(abi.encodePacked(currentBaseURI, _tokenId.toString(), uriSuffix))
            : '';
    }
        
    /**
     * @dev Returns the current base URI.
     * @return The base URI of the contract.
     */
    function _baseURI() internal view virtual override returns (string memory) {
        return baseURI;
    }

    function setApprovalForAll(address operator, bool approved) public  override onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }

    function approve(address operator, uint256 tokenId) public payable override onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        payable 
        override
        onlyAllowedOperator(from)
    {
        super.safeTransferFrom(from, to, tokenId, data);
    }


}

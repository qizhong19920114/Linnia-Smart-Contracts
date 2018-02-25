pragma solidity ^0.4.18;

import "node_modules/zeppelin-solidity/contracts/ownership/Ownable.sol";
import "node_modules/zeppelin-solidity/contracts/math/SafeMath.sol";
import "node_modules/zeppelin-solidity/contracts/token/ERC721/ERC721.sol";
import "node_modules/zeppelin-solidity/contracts/token/ERC721/ERC721Token.sol";
import "./LinniaHub.sol";
import "./LinniaRoles.sol";
import "./LinniaPermissions.sol";


contract LinniaRecords is Ownable, ERC721Token {
    using SafeMath for uint;

    struct FileRecord {
        address patient;
        uint sigCount;
        mapping (address => bool) signatures;
        uint irisScore;
        // For now the record types are
        // 0 nil, 1 Blood Pressure, 2 A1C, 3 HDL, 4 Triglycerides, 5 Weight
        uint recordType;
        // ipfs hash of the file encrypted to the owner
        // note that the owner may not be the patient
        bytes32 ipfsHash;
        uint timestamp; // time the file is added
    }

    event RecordAdded(bytes32 indexed fileHash, address indexed patient);
    event RecordSigAdded(bytes32 indexed fileHash, address indexed provider, uint irisScore);

    LinniaHub public hub;
    // all linnia records
    // filehash => record mapping
    mapping(bytes32 => FileRecord) public records;
    // reverse mapping: ipfsHash => sha256 fileHash
    mapping(bytes32 => bytes32) public ipfsRecords;

    /* Modifiers */
    modifier onlyFromProvider() {
        require(hub.rolesContract().isProvider(msg.sender) == true);
        _;
    }

    modifier onlyFromPatient() {
        require(hub.rolesContract().isPatient(msg.sender) == true);
        _;
    }

    /* Constructor */
    function LinniaRecords(LinniaHub _hub) public {
        hub = _hub;
    }

    /* External functions */
    function patientOf(bytes32 fileHash)
        external view returns (address)
    {
        return records[fileHash].patient;
    }

    function sigExists(bytes32 fileHash, address provider)
        external view returns (bool)
    {
        return records[fileHash].signatures[provider];
    }

    /* Constant functions */
    function recover(bytes32 message, bytes32 r, bytes32 s, uint8 v)
        public pure returns (address)
    {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(prefix, message);
        return ecrecover(prefixedHash, v, r, s);
    }

    /* Public functions */

    /// Add metadata to a medical record uploaded to IPFS by the patient,
    /// without any provider's signatures.
    /// @param fileHash the hash of the original unencrypted file
    /// @param recordType the type of the record
    /// @param ipfsHash the sha2-256 hash of the file on IPFS
    function addRecordByPatient(
        bytes32 fileHash, uint recordType, bytes32 ipfsHash)
        onlyFromPatient
        public
        returns (bool)
    {
        require(_addRecord(fileHash, msg.sender, recordType, ipfsHash));
        return true;
    }

    /// Add metadata to a medical record uploaded to IPFS by a provider
    /// @param fileHash the hash of the original unencrypted file
    /// @param patient the address of the patient
    /// @param recordType the type of the record
    /// @param ipfsHash the sha2-256 hash of the file on IPFS
    function addRecordByProvider(
        bytes32 fileHash, address patient, uint recordType, bytes32 ipfsHash)
        onlyFromProvider
        public
        returns (bool)
    {
        // add the file first
        require(_addRecord(fileHash, patient, recordType, ipfsHash));
        // add provider's sig to the file
        require(_addSig(fileHash, msg.sender));
        return true;
    }

    /// Add a provider's signature to an existing file
    /// This function is only callable by a provider
    /// @param fileHash the hash of the original file
    function addSigByProvider(bytes32 fileHash)
        onlyFromProvider
        public
        returns (bool)
    {
        require(_addSig(fileHash, msg.sender));
        return true;
    }

    /// Add a provider's signature to an existing file.
    /// This function can be called by anyone. As long as the signatures are
    /// indeed from a provider, the sig will be added to the file record
    /// @param fileHash the hash of the original file
    /// @param r signature: R
    /// @param s signature: S
    /// @param v signature: V
    function addSig(bytes32 fileHash, bytes32 r, bytes32 s, uint8 v)
        public
        returns (bool)
    {
        // recover the provider's address from signature
        address provider = recover(fileHash, r, s, v);
        // add sig
        require(_addSig(fileHash, provider));
        return true;
    }

    function addRecordByAdmin(
        bytes32 fileHash, address patient, address provider, uint recordType,
        bytes32 ipfsHash)
        onlyOwner
        public
        returns (bool)
    {
        require(_addRecord(fileHash, patient, recordType, ipfsHash));
        if (provider != 0) {
            require(_addSig(fileHash, provider));
        }
        return true;
    }

    // ERC-721 overrides
    function transfer(address _to, uint256 _tokenId) public onlyOwnerOf(_tokenId) {
        // XXX: right now the process of transferring a medical record ownership is
        // - owner re-encrypts the file and uploads to ipfs for the new owner
        // - owner gives the new owner permission to access the file in Permissions
        // - owner calls `transfer` here
        bytes32 fileHash = bytes32(_tokenId);
        // owner must first give access to the recipient
        require(_canAccessFile(fileHash, _to));
        // update the IPFS path of the file to be the new owner's
        bytes32 newIpfsHash = hub.permissionsContract().ipfsHash(fileHash, _to);
        records[fileHash].ipfsHash = newIpfsHash;
        ipfsRecords[newIpfsHash] = fileHash;
        super.transfer(_to, _tokenId);
    }

    function approve(address _to, uint256 _tokenId) public onlyOwnerOf(_tokenId) {
        bytes32 fileHash = bytes32(_tokenId);
        require(_canAccessFile(fileHash, _to));
        // XXX: what if the owner revokes access later?
        super.approve(_to, _tokenId);
    }

    function takeOwnership(uint256 _tokenId) public {
        bytes32 fileHash = bytes32(_tokenId);
        require(_canAccessFile(fileHash, msg.sender));
        // update the IPFS path of the file to be the new owner's
        bytes32 newIpfsHash = hub.permissionsContract().ipfsHash(fileHash, msg.sender);
        records[fileHash].ipfsHash = newIpfsHash;
        ipfsRecords[newIpfsHash] = fileHash;
        super.takeOwnership(_tokenId);
    }

    /* Private functions */
    function _addRecord(
        bytes32 fileHash, address patient, uint recordType, bytes32 ipfsHash)
        private
        returns (bool)
    {
        // validate input
        require(fileHash != 0 && recordType != 0 && ipfsHash != 0);
        // the file must be new
        require(
            records[fileHash].recordType == 0 && ipfsRecords[ipfsHash] == 0
        );
        // verify patient role
        require(hub.rolesContract().isPatient(patient) == true);
        // add record
        records[fileHash] = FileRecord({
            patient: patient,
            sigCount: 0,
            irisScore: 0,
            recordType: recordType,
            ipfsHash: ipfsHash,
            // solium-disable-next-line security/no-block-members
            timestamp: block.timestamp
        });
        // add the reverse mapping
        ipfsRecords[ipfsHash] = fileHash;
        // emit event
        RecordAdded(fileHash, patient);
        // mint token for the record
        _mint(patient, uint(fileHash));
        return true;
    }

    function _addSig(bytes32 fileHash, address provider)
        private
        returns (bool)
    {
        FileRecord storage record = records[fileHash];
        // the file must exist
        require(record.recordType != 0);
        // verify provider role
        require(hub.rolesContract().isProvider(provider) == true);
        // the provider must not have signed the file already
        require(!record.signatures[provider]);
        uint provenanceScore = hub.rolesContract().provenance(provider);
        // add signature
        record.sigCount = record.sigCount.add(provenanceScore);
        record.signatures[provider] = true;
        // update iris score
        record.irisScore = record.irisScore.add(provenanceScore);
        // emit event
        RecordSigAdded(fileHash, provider, record.irisScore);
        return true;
    }

    function _canAccessFile(bytes32 fileHash, address viewer)
        private view returns (bool)
    {
        return hub.permissionsContract().canAccessFile(fileHash, viewer);
    }
}

pragma solidity ^0.4.18;

import "node_modules/zeppelin-solidity/contracts/ownership/Ownable.sol";
import "./LinniaHub.sol";
import "./LinniaRecords.sol";


contract LinniaPermissions is Ownable {
    struct Permission {
        bool canAccess;
        // IPFS hash of the file, encrypted to the viewer
        bytes32 ipfsHash;
    }

    event AccessGranted(address indexed owner, address indexed viewer,
    bytes32 fileHash);
    event AccessRevoked(address indexed owner, address indexed viewer,
    bytes32 fileHash);

    LinniaHub public hub;
    // filehash => viewer => permission mapping
    mapping(bytes32 => mapping(address => Permission)) public permissions;

    /* Constructor */
    function LinniaPermissions(LinniaHub _hub) public {
        hub = _hub;
    }

    /* External functions */
    function canAccessFile(bytes32 fileHash, address viewer)
        external
        view
        returns (bool)
    {
        return permissions[fileHash][viewer].canAccess;
    }

    function ipfsHash(bytes32 fileHash, address viewer)
        external
        view
        returns (bytes32)
    {
        return permissions[fileHash][viewer].ipfsHash;
    }

    /* Public functions */

    /// Give a viewer access to a medical record
    /// @param fileHash the hash of the unencrypted file
    /// @param viewer the user being allowed to view the file
    /// @param ipfsHash the IPFS hash of the file encrypted to viewer
    function grantAccess(bytes32 fileHash, address viewer, bytes32 ipfsHash)
        public
        returns (bool)
    {
        // assert the file is owned by the sender
        require(hub.recordsContract().ownerOf(uint(fileHash)) == msg.sender);
        // access must not have already been granted
        require(!permissions[fileHash][viewer].canAccess);
        permissions[fileHash][viewer] = Permission({
            canAccess: true,
            ipfsHash: ipfsHash
        });
        AccessGranted(msg.sender, viewer, fileHash);
        return true;
    }

    /// Revoke a viewer access to a document
    /// Note that this does not remove the file off IPFS
    /// @param fileHash the hash of the unencrytped file
    /// @param viewer the user being allowed to view the file
    function revokeAccess(bytes32 fileHash, address viewer)
        public
        returns (bool)
    {
        // assert the file is owned by the sender
        require(hub.recordsContract().ownerOf(uint(fileHash)) == msg.sender);
        // access must have already been grated
        require(permissions[fileHash][viewer].canAccess);
        permissions[fileHash][viewer] = Permission({
            canAccess: false,
            ipfsHash: 0
        });
        AccessRevoked(msg.sender, viewer, fileHash);
        return true;
    }
}

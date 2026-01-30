// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract Registration {

    address public INCB;

    constructor() {
        INCB = msg.sender;
    }

    enum Role {NCA, Customs, Exporter, Logistics, Importer}

    struct NCA {
        Role role;
        bytes3 countryISO;
        bool registered;
    }

    struct Actor {
        Role role;
        bytes3 countryISO;
        bytes32 ipfsHash;
        uint256 licenseID;
        uint256 expiryDate;
        bool registered;
    }

    modifier onlyINCB {
        require((msg.sender==INCB), "Only INCB is authorized to call this function");
        _;
    }

    modifier onlyNCA(address actorAddr) {
        require((registeredNCAs[msg.sender].registered), "Only NCA is authorized to call this function");
        require(registeredActors[actorAddr].countryISO == registeredNCAs[msg.sender].countryISO, "Actor's country ISO does not match NCA's country ISO");
        _;
    }

    mapping(address=>NCA) public registeredNCAs;
    mapping(address=>Actor) public registeredActors;

    event NCAAdded(address NCAaddr, bytes3 countryISO);
    event ActorRequestedToRegister(address addr);
    event ActorRegistered(address addr, Role role, bytes3 countryISO);
    event ActorRegistrationRevoked(address addr);
    event NCARegistrationRevoked(address addr);
    
    function registerNCA(address NCAaddr, bytes3 ISO) public onlyINCB{
        require(!registeredNCAs[NCAaddr].registered, "NCA is already registered");
        registeredNCAs[NCAaddr] = NCA({
            role: Role.NCA,
            countryISO: ISO,
            registered: true
        });
        emit NCAAdded(NCAaddr, ISO);
    }

    function requestReg(address addr, bytes3 ISO, Role role, bytes32 ipfsHash) public {
        require(!registeredActors[addr].registered, "You are already registered");
        registeredActors[addr].role = role;
        registeredActors[addr].countryISO = ISO;
        registeredActors[addr].ipfsHash = ipfsHash;
        emit ActorRequestedToRegister(addr);
    }

    function approveReg(address addr, uint256 licenseId, uint256 expiryDate) public onlyNCA(addr){
        require(!registeredActors[addr].registered, "Actor is already registered");
        registeredActors[addr].licenseID = licenseId;
        registeredActors[addr].expiryDate = expiryDate;
        registeredActors[addr].registered = true;
        emit ActorRegistered(addr, registeredActors[addr].role, registeredActors[addr].countryISO);
    }

    function revokeReg(address addr) public onlyNCA(addr){
        require(registeredActors[addr].registered, "Actor is not registered");
        registeredActors[addr].registered = false;
        emit ActorRegistrationRevoked(addr);
    }

    function revokeNCAReg(address addr) public onlyINCB{
        require(registeredNCAs[addr].registered, "NCA is not registered");
        registeredNCAs[addr].registered = false;
        emit NCARegistrationRevoked(addr);
    }

    function updateLicense(address addr, uint256 expiryDate) public onlyNCA(addr){
        require(registeredActors[addr].registered, "Actor is not registered");
        registeredActors[addr].expiryDate = expiryDate;
        registeredActors[addr].registered = false;
    }

    function isNCARegistered(address addr) public view returns (bool) {
        return registeredNCAs[addr].registered;
    }

    function isLicensed(address addr) public view returns (bool) {
        return ((registeredActors[addr].registered) && (registeredActors[addr].expiryDate >= uint256(block.timestamp)));
    }

    function getActorRole(address addr) public view returns (Role) {
        return registeredActors[addr].role;
    }

    function getActorCountry(address addr) public view returns (bytes3) {
        return registeredActors[addr].countryISO;
    }

    function getNCACountry(address addr) public view returns (bytes3) {
        return registeredNCAs[addr].countryISO;
    }

}

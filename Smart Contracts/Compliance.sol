// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./Registration.sol";
import "./Shipping.sol";

contract Compliance {

    Registration regSC;
    Shipping shipSC;
    address INCB; //Owner
    address compSC;
    uint256 public exportId;
    uint256 public importId;
    string public ipfsCID;

    constructor(address regSCAddr) {
        regSC = Registration(regSCAddr);
        INCB = msg.sender;
        exportId = 1;
        importId = 1;
    }

    modifier onlyINCB {
        require((msg.sender==INCB), "Only INCB is authorized to call this function");
        _;
    }

    modifier onlyNCA(bytes3 country) {
        require((regSC.isNCARegistered(msg.sender)), "Only NCA is authorized to call this function");
        require(regSC.getNCACountry(msg.sender) == country, "NCA's country doesn't match");
        _;
    }

    modifier onlyRole(Registration.Role role) {
        require((regSC.isLicensed(msg.sender)), "Actor is not licensed");
        require((regSC.getActorRole(msg.sender)==role), "User is unauthorized to call this function");
        _;
    }

    enum PermitStatus {Pending, Approved, Revoked, Exhausted}

    struct Permit {
        uint256 shipmentId;
        uint256 expiryDate;
        bytes32 ipfsHash;
        PermitStatus status;
    }
    mapping(uint16 => bytes32) public INCBQuotas;
    mapping(uint256 => Permit) public exportPermits;
    mapping(uint256 => Permit) public importPermits;

    event IncbQuotasAdded(uint16 year, bytes32 ipfsHash);
    event ExportPermitRequested(uint256 permitId, uint256 shipmentId);
    event ImportPermitRequested(uint256 permitId, uint256 shipmentId);
    event ExportPermitApproved(uint256 id);
    event ImportPermitApproved(uint256 id);
    event ExportPermitRevoked(uint256 id);
    event ImportPermitRevoked(uint256 id);
    event ExportQuotaConsumed(bytes3 country, bytes32 substance, uint16 year, uint256 qty);
    event ImportQuotaConsumed(bytes3 country, bytes32 substance, uint16 year, uint256 qty);

    function setIncpQuotas(uint16 year, bytes32 ipfsHash) public onlyINCB{
        INCBQuotas[year] = ipfsHash;
        emit IncbQuotasAdded(year, ipfsHash);
    }

    function requestExportPermit(uint256 shipmentId, bytes32 ipfsHash) public onlyRole(Registration.Role.Exporter) {
        exportPermits[exportId].shipmentId = shipmentId;
        exportPermits[exportId].ipfsHash= ipfsHash;
        exportPermits[exportId].status = PermitStatus.Pending;
        emit ExportPermitRequested(exportId++, shipmentId);
    }

    function requestImportPermit(uint256 shipmentId, bytes32 ipfsHash) public onlyRole(Registration.Role.Importer){
        importPermits[importId].shipmentId = shipmentId;
        importPermits[importId].ipfsHash= ipfsHash;
        importPermits[importId].status = PermitStatus.Pending;
        emit ImportPermitRequested(importId++, shipmentId);
    }

    function approveExportPermit(uint256 id, uint256 expiryDate) public onlyNCA(shipSC.getSource(exportPermits[id].shipmentId)){
        exportPermits[id].expiryDate = expiryDate;
        exportPermits[id].status = PermitStatus.Approved;
        shipSC.setExportPermitId(id);
        emit ExportPermitApproved(id);
    }

    function approveImportPermit(uint256 id, uint256 expiryDate) public onlyNCA(shipSC.getDest(importPermits[id].shipmentId)){
        require(regSC.isLicensed(shipSC.getImporter(importPermits[id].shipmentId)), "Importer is not licensed");
        importPermits[id].expiryDate = expiryDate;
        importPermits[id].status = PermitStatus.Approved;
        shipSC.setImportPermitId(id);
        emit ImportPermitApproved(id);
    }

    function revokeExportPermit(uint256 id) public onlyNCA(shipSC.getSource(exportPermits[id].shipmentId)) {
        require((exportPermits[id].status == PermitStatus.Approved), "Invalid permit status");
        exportPermits[id].status = PermitStatus.Revoked;
        emit ExportPermitRevoked(id);
    }

    function revokeImportPermit(uint256 id) public onlyNCA(shipSC.getDest(importPermits[id].shipmentId)) {
        require((importPermits[id].status == PermitStatus.Approved), "Invalid permit status");
        importPermits[id].status = PermitStatus.Revoked;
        emit ImportPermitRevoked(id);
    }

    /*
    function consumeOnExportClear(uint256 exportPermitId) external {
        require(msg.sender == compSC, "Unauthorized caller");
        require((isExportPermitValid(exportPermitId)), "Permit is invalid");
        Quota storage q = quotas[shipSC.getSource(exportPermits[exportPermitId].shipmentId)][shipSC.getSubstance(exportPermits[exportPermitId].shipmentId)][shipSC.getYear(exportPermits[exportPermitId].shipmentId)];
        //require(qe.reservedExport >= e.qty, "Insufficient Quota");
        q.reservedExport -= shipSC.getQuantity(exportPermits[exportPermitId].shipmentId);
        q.usedExport += shipSC.getQuantity(exportPermits[exportPermitId].shipmentId);
        exportPermits[exportPermitId].status = PermitStatus.Exhausted;
    }

    function consumeOnImportClear(uint256 importPermitId) external {
        require(msg.sender == compSC, "Unauthorized caller");
        require((isExportPermitValid(importPermitId)), "Permit is invalid");
        //Quota storage qe = quotas[e.countryFrom][e.substance][e.year];
        Quota storage q = quotas[shipSC.getDest(importPermits[importPermitId].shipmentId)][shipSC.getSubstance(importPermits[importPermitId].shipmentId)][shipSC.getYear(importPermits[importPermitId].shipmentId)];
        require(q.reservedImport >= shipSC.getQuantity(importPermits[importPermitId].shipmentId), "Insufficient Quota");
        q.reservedImport -= shipSC.getQuantity(importPermits[importPermitId].shipmentId);
        q.usedImport += shipSC.getQuantity(importPermits[importPermitId].shipmentId);
        importPermits[importPermitId].status = PermitStatus.Exhausted;
        //emit QuotaConsumed(pairId, i.countryFrom, i.countryTo, i.substance, i.year, i.qty);
    }
    */

    function isExportPermitValid(uint256 id) public view returns (bool) {
        return (exportPermits[id].status == PermitStatus.Approved && exportPermits[id].expiryDate >= uint64(block.timestamp));
    }

    function isImportPermitValid(uint256 id) public view returns (bool) {
        return (importPermits[id].status == PermitStatus.Approved && importPermits[id].expiryDate >= uint64(block.timestamp));
    }

    function getIncbCapIpfs() public view returns (string memory) {
        return(ipfsCID);
    }

    function getExportPermitHash(uint256 id) public view returns (bytes32) {
        return(exportPermits[id].ipfsHash);
    }

    function getImportPermitHash(uint256 id) public view returns (bytes32) {
        return(importPermits[id].ipfsHash);
    }

}

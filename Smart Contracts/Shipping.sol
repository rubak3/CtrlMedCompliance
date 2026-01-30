// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./Registration.sol";
import "./Compliance.sol";

contract Shipping {

    Registration immutable regSC;
    Compliance immutable compSC;
    address INCB; //Owner
    uint256 public shipmentId;
    address compScAddr;

    constructor(address regSCAddr, address compSCAddr) {
        regSC = Registration(regSCAddr);
        compSC = Compliance(compSCAddr);
        compScAddr = compSCAddr;
        INCB = msg.sender;
        shipmentId = 1;
    }

    modifier onlyINCB {
        require((msg.sender==INCB), "Only INCB is authorized to call this function");
        _;
    }

    modifier onlyCompSC {
        require((msg.sender==compScAddr), "Only Compliance SC is authorized to call this function");
        _;
    }

    modifier onlyRole(Registration.Role role) {
        require((regSC.isLicensed(msg.sender)), "Actor is not licensed");
        require((regSC.getActorRole(msg.sender)==role), "User is unauthorized to call this function");
        _;
    }

    enum State {Created, ExportCleared, ApprovedByINCB, InTransit, ImportCleared, Received}

    struct Shipment {
        address exporter;
        address importer;
        address currentCustodian;
        bytes3  originISO;
        bytes3  destISO;
        bytes32 substance;
        uint256 quantity;
        bytes32 ipfsHash;
        uint256 exportPermitId;
        uint256 importPermitId;
        uint16 year;
        State   state;
    }

    mapping(uint256=>Shipment) public shipments;

    event ExportCleared(uint256 shippmentId);
    event ImportCleared(uint256 shippmentId);
    event ExportQuotaConsumed(bytes3 country, bytes32 substance, uint16 year, uint256 qty);
    event ImportQuotaConsumed(bytes3 country, bytes32 substance, uint16 year, uint256 qty);

    function createShipment(address importer, bytes32 substance, uint256 qty, uint16 year, bytes32 ipfsHash) public onlyRole(Registration.Role.Exporter){
        shipments[shipmentId].exporter         = msg.sender;
        shipments[shipmentId].importer         = importer;
        shipments[shipmentId].currentCustodian = msg.sender;
        shipments[shipmentId].originISO        = regSC.getActorCountry(msg.sender);
        shipments[shipmentId].destISO          = regSC.getActorCountry(importer);
        shipments[shipmentId].substance        = substance;
        shipments[shipmentId].quantity         = qty;
        shipments[shipmentId].year             = year;
        shipments[shipmentId].ipfsHash         = ipfsHash;
        shipments[shipmentId].state            = State.Created;
    }

    function approveExportClearance(uint256 id) public onlyRole(Registration.Role.Customs){
        require((regSC.getActorCountry(msg.sender) == shipments[id].originISO), "Country mismatch");
        require(compSC.isExportPermitValid(shipments[id].exportPermitId), "Export permit is invalid");
        shipments[id].state = State.ExportCleared;
        emit ExportCleared(id);
    }

    function approveForShipping(uint256 id) public onlyINCB(){
        require(shipments[id].state == State.ExportCleared,"Shipment not cleared by export customs");
        shipments[id].state = State.ApprovedByINCB;
    }

    function pickup(uint256 id) public onlyRole(Registration.Role.Logistics){
        require(shipments[id].state == State.ApprovedByINCB, "Shipment not approved by INCB for international shipping");
        shipments[id].currentCustodian = msg.sender;
        shipments[id].state = State.InTransit;
        emit ExportQuotaConsumed(shipments[id].originISO, shipments[id].substance, shipments[id].year, shipments[id].quantity);
    }

    function approveImportClearance(uint256 id) public onlyRole(Registration.Role.Customs){
        require((regSC.getActorCountry(msg.sender) == shipments[id].destISO), "Country mismatch");
        require(compSC.isImportPermitValid(shipments[id].importPermitId), "Import permit is invalid");
        shipments[id].state = State.ImportCleared;
        emit ImportCleared(id);
        emit ImportQuotaConsumed(shipments[id].destISO, shipments[id].substance, shipments[id].year, shipments[id].quantity);
    }

    function receiveShipment(uint256 id) public onlyRole(Registration.Role.Importer) {
        require(msg.sender == shipments[id].importer, "Not intended importer");
        shipments[id].state = State.Received;
        shipments[id].currentCustodian = msg.sender;
    }

    function getSource(uint256 id) public view returns (bytes3) {
        return(shipments[id].originISO);
    }

    function getExporter(uint256 id) public view returns (address) {
        return(shipments[id].exporter);
    }

    function getDest(uint256 id) public view returns (bytes3) {
        return(shipments[id].destISO);
    }

    function getImporter(uint256 id) public view returns (address) {
        return(shipments[id].importer);
    }

    function getSubstance(uint256 id) public view returns (bytes32) {
        return(shipments[id].substance);
    }

    function getYear(uint256 id) public view returns (uint16) {
        return(shipments[id].year);
    }

    function getQuantity(uint256 id) public view returns (uint256) {
        return(shipments[id].quantity);
    }

    function getShipmentDetails(uint256 id) public view returns (Shipment memory) {
        return(shipments[id]);
    }

    function getShipmentIpfsHash(uint256 id) public view returns (bytes32) {
        return shipments[id].ipfsHash;
    }

    function setExportPermitId(uint256 id) public onlyCompSC{
        shipments[id].exportPermitId = id;
    }

    function setImportPermitId(uint256 id) public onlyCompSC{
        shipments[id].importPermitId = id;
    }

}

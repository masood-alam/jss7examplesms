package com.vectracom.jss7.standalone.example;

import java.nio.charset.Charset;
import java.sql.Timestamp;
import java.util.Date;

import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.NumberingPlan;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.AspImpl;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.MAPSmsTpduParameterFactory;
import org.mobicents.protocols.ss7.map.api.datacoding.NationalLanguageIdentifier;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPDialogSms;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.mobicents.protocols.ss7.map.api.smstpdu.AbsoluteTimeStamp;
import org.mobicents.protocols.ss7.map.api.smstpdu.AddressField;
import org.mobicents.protocols.ss7.map.api.smstpdu.DataCodingScheme;
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsDeliverTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserData;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserDataHeader;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserDataHeaderElement;
import org.mobicents.protocols.ss7.map.service.sms.SmsSignalInfoImpl;
import org.mobicents.protocols.ss7.map.smstpdu.AbsoluteTimeStampImpl;
import org.mobicents.protocols.ss7.map.smstpdu.ProtocolIdentifierImpl;
import org.mobicents.protocols.ss7.map.smstpdu.SmsDeliverTpduImpl;
import org.mobicents.protocols.ss7.map.smstpdu.UserDataImpl;
import org.mobicents.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.mobicents.protocols.ss7.sccp.impl.parameter.DefaultEncodingScheme;
import org.mobicents.protocols.ss7.sccp.impl.parameter.GlobalTitle0100Impl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.mobicents.protocols.ss7.sccp.parameter.EncodingScheme;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle0100;
import org.mobicents.protocols.ss7.sccp.parameter.ParameterFactory;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;
import org.mobicents.protocols.ss7.map.api.smstpdu.TypeOfNumber;
import org.mobicents.protocols.ss7.map.api.smstpdu.NumberingPlanIdentification;

public class Client extends AbstractSctpBase {
	private static Logger logger = Logger.getLogger(Client.class);

	// SCTP
	private ManagementImpl sctpManagement;

	// M3UA
	private M3UAManagementImpl clientM3UAMgmt;

	// SCCP
	private SccpStackImpl sccpStack;
//	private SccpResource sccpResource;

	// TCAP
	private TCAPStack tcapStack;

	// MAP
	private MAPStackImpl mapStack;
	private MAPProvider mapProvider;

	private ParameterFactory sccpParameterFact=null;
	protected MAPSmsTpduParameterFactory mapSmsTpduParameterFactory=null;
	
	private static Charset isoCharset = Charset.forName("ISO-8859-1");

	
	 private MAPApplicationContext sriMAPApplicationContext;
	 private SccpAddress serviceCenterSCCPAddress=null;
	  private AddressString serviceCenterAddress;
	 private SccpAddress hlrSCCPAddress;
	 private String SC_ADDRESS="22221";
	 private String HLR_GT="923335681111";

	 
	 // replacement of CMPs
	 SendRoutingInfoForSMResponse sendRoutingInfoForSMResponse=null;
	//  InformServiceCenterContainer informServiceCenterContainer;
	 
	/**
	 * 
	 */
	public Client() {

		
	}

	protected void initializeStack(IpChannelType ipChannelType) throws Exception {

		this.initSCTP(ipChannelType);

		// Initialize M3UA first
		this.initM3UA();

		// Initialize SCCP
		this.initSCCP();

		// Initialize TCAP
		this.initTCAP();

		// Initialize MAP
		this.initMAP();

		// FInally start ASP
		// Set 5: Finally start ASP
		this.clientM3UAMgmt.startAsp("ASP1");
	}

	// Server Mode SCTP association (SMSCGATEWAY approach)
	private void initSCTP(IpChannelType ipChannelType) throws Exception {
		logger.debug("Initializing SCTP Stack ....");
		
		
		if (Configuration.Serverside == true)
		{
			// server configuration of SCTP
			this.sctpManagement = new ManagementImpl("Client");
			this.sctpManagement.start();
			this.sctpManagement.removeAllResourses();
			this.sctpManagement.setConnectDelay(10000);
			// 1. Create SCTP Server
			sctpManagement.addServer(CLIENT_NAME, CLIENT_IP, CLIENT_PORT, ipChannelType, null);
			// 2. Create SCTP Server Association
			sctpManagement
			.addServerAssociation(SERVER_IP, SERVER_PORT, CLIENT_NAME, CLIENT_ASSOCIATION_NAME, ipChannelType);
			// 3. Start Server
			sctpManagement.startServer(CLIENT_NAME);
			
		}
		else {
			
			 this.sctpManagement = new ManagementImpl("Client");
			 this.sctpManagement.setSingleThread(true);
			 this.sctpManagement.start();
			 this.sctpManagement.setConnectDelay(5000);
			 this.sctpManagement.removeAllResourses();

			 // 1. Create SCTP Association
			 sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, 
					CLIENT_ASSOCIATION_NAME, ipChannelType, null);
			
		}
		

		
		
		logger.debug("Initialized SCTP Stack ....");
}	
	
	private void initM3UA() throws Exception {
		logger.debug("Initializing M3UA Stack ....");
		
		// server side configuration
		this.clientM3UAMgmt = new M3UAManagementImpl("Client-Mtp3UserPart", "Restcomm");
		this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
		//this.clientM3UAMgmt.start();
		//this.clientM3UAMgmt.removeAllResourses();
		// Step 1 : Create App Server
		RoutingContext rc = factory
				.createRoutingContext(new long[] { ROUTING_CONTEXT });
		NetworkAppearance na = factory.createNetworkAppearance(0l);

	if (Configuration.Serverside == true ) {

		TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
		this.clientM3UAMgmt
		.createAs("AS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc,
			trafficModeType, 1, null);
	}
	else {
		
			// client side configuration of M3UA
			// m3ua as create rc <rc> <ras-name>
			TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
			this.clientM3UAMgmt.createAs("AS1", Functionality.IPSP, ExchangeType.SE, 
					IPSPType.CLIENT, 
					rc, 
					trafficModeType, 
					1, null);//na);
	
	}
	// Step 2 : Create ASP
	this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);
	// Step3 : Assign ASP to AS
	AspImpl asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");
	// Step 4: Add Route. Remote point code is 2
	clientM3UAMgmt.addRoute(SERVER_SPC, -1, -1, "AS1");
	this.clientM3UAMgmt.start();


	logger.debug("Initialized M3UA Stack ....");
}	

	

	private void initSCCP() throws Exception {
		logger.debug("Initializing SCCP Stack ....");
		this.sccpStack = new SccpStackImpl("Client-SccpStack");
		this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

		this.sccpStack.start();
		this.sccpStack.removeAllResourses();

		 this.sccpStack.getSccpResource().addRemoteSpc(1, SERVER_SPC, 0, 0);
		 // Typically this example, remote has only one Application with single ssn (both hlr and msc together : hack)
         this.sccpStack.getSccpResource().addRemoteSsn(1, SERVER_SPC,  SERVER_SSN, 0, false);
//         this.sccpStack.getSccpResource().addRemoteSsn(2, SERVER_SPC,  6, 0, false);

         this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0);
         this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);
         // configure gtt address
         GlobalTitle gt = null;
         EncodingScheme ec = new BCDEvenEncodingScheme();
         
//         org.mobicents.protocols.ss7.indicator.NumberingPlan np = org.mobicents.protocols.ss7.indicator.NumberingPlan.valueOf(1);
//         NatureOfAddress nai = NatureOfAddress.valueOf(4);
         gt = new GlobalTitle0100Impl("000", 0, ec,  org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);
         SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, SERVER_SPC, 0 );
         this.sccpStack.getRouter().addRoutingAddress(1, localAddress);
         gt = new GlobalTitle0100Impl("*", 0, ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);            
         SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, SERVER_SPC, 0 );
         this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern, "K", 1, -1, null, 0);

         
         
         
         gt = new GlobalTitle0100Impl("000", 0, ec,  org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);
         SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, CLIENT_SPC, 0 );
         this.sccpStack.getRouter().addRoutingAddress(2, remoteAddress);
//         gt = new GlobalTitle0001Impl("*", nai);            
         gt = new GlobalTitle0100Impl("*", 0, ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);            
         pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, CLIENT_SPC, 0 );
         this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern, "K", 2, -1, null, 0);

		
 		if (this.sccpParameterFact == null)
			this.sccpParameterFact = new ParameterFactoryImpl();
		
		logger.debug("Initialized SCCP Stack ....");
	}

	private void initTCAP() throws Exception {
		logger.debug("Initializing TCAP Stack ....");
		this.tcapStack = new TCAPStackImpl("Client-TcapStackMap", this.sccpStack.getSccpProvider(), CLIENT_SSN);
		this.tcapStack.start();
		this.tcapStack.setDialogIdleTimeout(60000);
		this.tcapStack.setInvokeTimeout(30000);
		this.tcapStack.setMaxDialogs(2000);
		logger.debug("Initialized TCAP Stack ....");
	}

	private void initMAP() throws Exception {
		logger.debug("Initializing MAP Stack ....");
		this.mapStack = new MAPStackImpl("Client-MapStack", this.tcapStack.getProvider());
	
		this.mapProvider = this.mapStack.getMAPProvider();

		this.mapProvider.addMAPDialogListener( this);
		this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

		this.mapProvider.getMAPServiceSms().acivate();

	
		this.mapStack.start();
		
		if (this.mapSmsTpduParameterFactory == null)
			  this.mapSmsTpduParameterFactory = this.mapProvider.getMAPSmsTpduParameterFactory();
		
		logger.debug("Initialized MAP Stack ....");
	}

	
	
	 private SccpAddress getServiceCenterSccpAddress() {
	        EncodingScheme encodingScheme = new DefaultEncodingScheme();
	        if (this.serviceCenterSCCPAddress == null) {
	            GlobalTitle0100 gt = new GlobalTitle0100Impl(SC_ADDRESS, 0, encodingScheme,
	                    NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);
	            this.serviceCenterSCCPAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, CLIENT_SSN);
	        }
	        return this.serviceCenterSCCPAddress;
	    }
	 
	 
	 private MAPApplicationContext getSRIMAPApplicationContext() {
	        if (this.sriMAPApplicationContext == null) {
	            this.sriMAPApplicationContext = MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgGatewayContext,
	                    MAPApplicationContextVersion.version3);
	        }
	        return this.sriMAPApplicationContext;
	    }

	    private ISDNAddressString getCalledPartyISDNAddressString(String destinationAddress) {
	        return this.mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
	                org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan.ISDN, destinationAddress);
	    }

	    private SccpAddress msisdnToSccpAddress(String msisdn){
	        EncodingScheme encodingScheme = new DefaultEncodingScheme();
	        GlobalTitle globalTitle = new GlobalTitle0100Impl(msisdn, 0, encodingScheme,
	                NumberingPlan.ISDN_TELEPHONY, NatureOfAddress.INTERNATIONAL);
	        return new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, globalTitle, 0, SERVER_SSN);
	    }

	    private AddressString getServiceCenterAddressString() {
	        if (this.serviceCenterAddress == null) {
	            this.serviceCenterAddress = this.mapProvider.getMAPParameterFactory()
	            		.createAddressString(AddressNature.international_number,
	                    org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan.ISDN, SC_ADDRESS);
	        }
	        return this.serviceCenterAddress;
	    }

	    private MAPDialogSms setupRoutingInfoForSMRequestIndication(String destinationAddress) throws MAPException {
	        SccpAddress cdpa = this.msisdnToSccpAddress(destinationAddress);

	        MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(this.getSRIMAPApplicationContext(), 
	        		this.getServiceCenterSccpAddress(), null, 
	        		cdpa, null);

	        mapDialogSms.addSendRoutingInfoForSMRequest(this.getCalledPartyISDNAddressString(destinationAddress), true,
	                this.getServiceCenterAddressString(), null, false, null, null, null);

	        return mapDialogSms;
	    }

	    public void sendSRI(String msisdn) {
	        // Send out SRI-SM
	        MAPDialogSms mapDialogSms = null;
	        try {
	            mapDialogSms = this.setupRoutingInfoForSMRequestIndication(msisdn);
	         //   mapDialogSms.setUserObject(true);
	          //  if (mapDialogSms.getUserObject() != null) {
	          //  	logger.info("*******************************************");
	          //  }
	            mapDialogSms.send();
	        } catch (MAPException e) {
	            System.out.println("Error while trying to send RoutingInfoForSMRequestIndication");
	            mapDialogSms.release();
	        }
	    }	 
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		System.out.println("*************************************");
		System.out.println("***          SmsClient           ***");
		System.out.println("*************************************");
		IpChannelType ipChannelType = IpChannelType.SCTP;
		if (args.length >= 1 && args[0].toLowerCase().equals("tcp"))
			ipChannelType = IpChannelType.TCP;

		Client client = new Client();
		
		try {
			client.initializeStack(ipChannelType);

			// Lets pause for 20 seconds so stacks are initialized properly
			Thread.sleep(20000);

			//client.initiateUSSD();
			client.sendSRI("1111");
			//client.initiateATI();

			Thread.sleep(20000);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	 protected AddressString getServiceCenterAddressString(int networkId) {
	            if (this.serviceCenterAddress == null) {
	                this.serviceCenterAddress = this.mapProvider.getMAPParameterFactory()
	                		.createAddressString(AddressNature.international_number,
	                        org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan.ISDN, "22221");
	            }
	            return this.serviceCenterAddress;
	    }	
	 protected SccpAddress getServiceCenterSccpAddress(int networkId) {
			NumberingPlan np = NumberingPlan.ISDN_TELEPHONY;
			NatureOfAddress na = NatureOfAddress.INTERNATIONAL;

			GlobalTitle gt = sccpParameterFact.createGlobalTitle("22221", 0, np, null, na);
			if (this.serviceCenterSCCPAddress == null) {
	            this.serviceCenterSCCPAddress = sccpParameterFact.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,gt, 0, CLIENT_SSN);
	        }
			return this.serviceCenterSCCPAddress;
	 }
	
	private SccpAddress getMSCSccpAddress(ISDNAddressString networkNodeNumber) {

		
		NumberingPlan np = NumberingPlan.ISDN_TELEPHONY;
		NatureOfAddress na = NatureOfAddress.INTERNATIONAL;
		GlobalTitle gt = sccpParameterFact.createGlobalTitle(networkNodeNumber.getAddress(), 
				0, np, null, na);
//        return MessageUtil.getSccpAddress(sccpParameterFact, networkNodeNumber.getAddress(), networkNodeNumber.getAddressNature().getIndicator(),
  //              networkNodeNumber.getNumberingPlan().getIndicator(), smscPropertiesManagement.getMscSsn(), smscPropertiesManagement.getGlobalTitleIndicator(),
    //            smscPropertiesManagement.getTranslationType());
        return sccpParameterFact.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE,gt, 0, CLIENT_SSN);
        
	}	
	
	private MAPApplicationContext getMtFoSMSMAPApplicationContext(
			MAPApplicationContextVersion mapApplicationContextVersion) {

		if (mapApplicationContextVersion == MAPApplicationContextVersion.version1) {
			return MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgMORelayContext,
					mapApplicationContextVersion);
		} else {
			return MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgMTRelayContext,
					mapApplicationContextVersion);
		}
	}

	private AddressField getSmsTpduOriginatingAddress(int ton, int npi, String address) {
        return this.mapSmsTpduParameterFactory.createAddressField(TypeOfNumber.getInstance(ton),
                NumberingPlanIdentification.getInstance(npi), address);
	}
	
	
	private void onSriFullResponse() throws MAPException {
		if (sendRoutingInfoForSMResponse != null) {
			Sms sms = new Sms();
		
			sms.setShortMessageText("Hello World");
	        sms.setSourceAddr("6666");
	        sms.setSourceAddrTon(-1);
	        sms.setSourceAddrNpi(-1);
	        sms.setSubmitDate(new Timestamp(System.currentTimeMillis()));

			ISDNAddressString networkNodeNumber = sendRoutingInfoForSMResponse.getLocationInfoWithLMSI().getNetworkNodeNumber();
			logger.info("networkNode="+sendRoutingInfoForSMResponse.getLocationInfoWithLMSI());
			String imsiData = this.sendRoutingInfoForSMResponse.getIMSI().getData();
			logger.info("imsi="+ imsiData);
			// SriSbb, this method will fire SendMtEvent to schedulerActivityContextInterface
//			executeForwardSM(smsSet, sendRoutingInfoForSMResponse.getLocationInfoWithLMSI(),
	//				sendRoutingInfoForSMResponse.getIMSI().getData(),smsSet.getNetworkId());
			// here we handle it by ourselves (copy of MtSbb.sendMtSms() 

			 IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(imsiData);
			
			 
//			SccpAddress networkNodeSccpAddress = this.getMSCSccpAddress(networkNodeNumber);
			AddressString scAddress = this.getServiceCenterAddressString(0);
			
			int sourceAddrTon = 0;
			int sourceAddrNpi = 0;
			
			SM_RP_DA sm_RP_DA = this.mapProvider.getMAPParameterFactory().createSM_RP_DA(imsi);
			SM_RP_OA sm_RP_OA = this.mapProvider.getMAPParameterFactory().createSM_RP_OA_ServiceCentreAddressOA(scAddress);
			DataCodingScheme dataCodingScheme = this.mapSmsTpduParameterFactory.createDataCodingScheme(16);	// not 15
			
			UserDataImpl ud = new UserDataImpl(new String(sms.getShortMessageText()), dataCodingScheme, null, isoCharset);
			
			Date submitDate = sms.getSubmitDate();
			AbsoluteTimeStampImpl serviceCentreTimeStamp = new AbsoluteTimeStampImpl((submitDate.getYear() % 100),
					(submitDate.getMonth() + 1), submitDate.getDate(), submitDate.getHours(), submitDate.getMinutes(),
					submitDate.getSeconds(), (submitDate.getTimezoneOffset() / 15));
			
			ProtocolIdentifierImpl pi = new ProtocolIdentifierImpl(0);
			// TODO : Take care of esm_class to include UDHI. See SMPP specs

			SmsDeliverTpduImpl smsDeliverTpduImpl = new SmsDeliverTpduImpl(false, false, false, true,
						this.getSmsTpduOriginatingAddress(sms.getSourceAddrTon(), sms.getSourceAddrNpi(),
						sms.getSourceAddr()), pi, serviceCentreTimeStamp, ud);

			SmsSignalInfoImpl smsSignalInfo = new SmsSignalInfoImpl(smsDeliverTpduImpl, null);
			
			MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms()
					.createNewDialog(getMtFoSMSMAPApplicationContext(MAPApplicationContextVersion.version3),
							this.getServiceCenterSccpAddress(0), 
							null, 
							this.getMSCSccpAddress(networkNodeNumber), 
							null);
			
			
			// sms is prepare in TxSmppServerSbb, with sms.setSourceAddr, sms.setSourceAddrTon, sms.setSourceAddrNpi
			
				// strictly map version 3
			mapDialogSms.addMtForwardShortMessageRequest(sm_RP_DA, sm_RP_OA, smsSignalInfo, false, null);
			mapDialogSms.send();
			
		}
	}
	

	@Override
	public void onDialogAccept(MAPDialog arg0, MAPExtensionContainer arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogClose(MAPDialog arg0) {
//	    try {

  //          this.onSriFullResponse();
    //    } catch (Throwable e1) {
        //    logger.error("Exception in onDialogClose when fetching records and issuing events: " + e1.getMessage(), e1);
  //          markDeliveringIsEnded(true);
      //  }	
	}

	@Override
	public void onDialogDelimiter(MAPDialog mapDialog) {
		// TODO Auto-generated method stub
	//	  try {
	  //          this.onSriFullResponse();
	    //    } catch (Throwable e1) {
	      //      logger.error("Exception in onDialogDelimiter when fetching records and issuing events: " + e1.getMessage(), e1);
	         //   markDeliveringIsEnded(true);
	       // }	
	}

	@Override
	public void onDialogNotice(MAPDialog arg0, MAPNoticeProblemDiagnostic arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogProviderAbort(MAPDialog arg0,
			MAPAbortProviderReason arg1, MAPAbortSource arg2,
			MAPExtensionContainer arg3) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogReject(MAPDialog arg0, MAPRefuseReason arg1,
			ApplicationContextName arg2, MAPExtensionContainer arg3) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogRelease(MAPDialog arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogRequest(MAPDialog arg0, AddressString arg1,
			AddressString arg2, MAPExtensionContainer arg3) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogRequestEricsson(MAPDialog arg0, AddressString arg1,
			AddressString arg2, IMSI arg3, AddressString arg4) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogTimeout(MAPDialog arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogUserAbort(MAPDialog arg0, MAPUserAbortChoice arg1,
			MAPExtensionContainer arg2) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onAlertServiceCentreRequest(AlertServiceCentreRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onAlertServiceCentreResponse(AlertServiceCentreResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onForwardShortMessageRequest(ForwardShortMessageRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onForwardShortMessageResponse(ForwardShortMessageResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onInformServiceCentreRequest(InformServiceCentreRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMoForwardShortMessageResponse(
			MoForwardShortMessageResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMtForwardShortMessageResponse(
			MtForwardShortMessageResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onReadyForSMRequest(ReadyForSMRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onReadyForSMResponse(ReadyForSMResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onReportSMDeliveryStatusRequest(
			ReportSMDeliveryStatusRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onReportSMDeliveryStatusResponse(
			ReportSMDeliveryStatusResponse arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMResponse) {
		// TODO Auto-generated method stub
	
		// SriSbb is invoked on event onSms(smsSetEvent, aci, eventContext), where
		// it checks preloaded routing info,
		// if not present, it calls method sendSRI(smsSet, destinationAddress,
		//ton, npi, mapApplicationContext) ,
		// on response here it uses two CMPs
		//this.setInformServiceCenterContainer(informServiceCenterContainer);
		//this.setSendRoutingInfoForSMResponse(evt);
		// these CMPs are used in further onDialogDelimiter (see there)
		this.sendRoutingInfoForSMResponse = sendRoutingInfoForSMResponse;
		try {
			onSriFullResponse();
		} catch (MAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void onErrorComponent(MAPDialog arg0, Long arg1, MAPErrorMessage arg2) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onInvokeTimeout(MAPDialog arg0, Long arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onMAPMessage(MAPMessage arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onRejectComponent(MAPDialog arg0, Long arg1, Problem arg2,
			boolean arg3) {
		// TODO Auto-generated method stub
		
	}

	public final class Configuration {
		  //set to false to allow compiler to identify and eliminate
		  //unreachable code
		  public static final boolean Serverside = false;
		} 
	
}

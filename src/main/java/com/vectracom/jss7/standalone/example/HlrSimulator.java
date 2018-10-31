package com.vectracom.jss7.standalone.example;

import java.nio.charset.Charset;

import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.AspImpl;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPParameterFactoryImpl;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
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
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
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
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsDeliverTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.SmsTpdu;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserData;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserDataHeader;
import org.mobicents.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.mobicents.protocols.ss7.sccp.impl.parameter.GlobalTitle0100Impl;
import org.mobicents.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.mobicents.protocols.ss7.sccp.parameter.EncodingScheme;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

public class HlrSimulator extends AbstractSctpBase {
	private static Logger logger = Logger.getLogger(HlrSimulator.class);

	// SCTP
	private ManagementImpl sctpManagement;
//	private NettySctpManagementImpl sctpManagement;

	// M3UA
	private M3UAManagementImpl M3UAMgmt;
	// SCCP
	private SccpStackImpl sccpStack;
	// TCAP
	private TCAPStack tcapStack;

	// MAP
	private MAPStackImpl mapStack;
	private MAPProvider mapProvider;

		// adapted from ss7/tools/simulator/tests/sms/TestSmsClientMan.java
	  private boolean needSendSend = false;
	  private boolean needSendClose = false;	
	
		private static Charset isoCharset = Charset.forName("ISO-8859-1");

		private void initSCTP(IpChannelType ipChannelType) throws Exception {
			logger.debug("Initializing SCTP Stack ....");
			/*
			if (Configuration.Serverside == true) {
				
				// server configuration of SCTP
					this.sctpManagement = new ManagementImpl("Server");
//					this.sctpManagement = new NettySctpManagementImpl("Server");
//					this.sctpManagement.setSingleThread(true);
					this.sctpManagement.start();
					this.sctpManagement.removeAllResourses();

					this.sctpManagement.setConnectDelay(10000);
					// 1. Create SCTP Server
					sctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, ipChannelType, null);

					// 2. Create SCTP Server Association
					sctpManagement
					.addServerAssociation(CLIENT_IP, CLIENT_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, ipChannelType);
					
					// 3. Start Server
					sctpManagement.startServer(SERVER_NAME);
			
				
			}
			else {
			this.sctpManagement = new ManagementImpl("Server");
			this.sctpManagement.setSingleThread(true);
			this.sctpManagement.start();
			this.sctpManagement.setConnectDelay(5000);
			this.sctpManagement.removeAllResourses();

			// 1. Create SCTP Association
			sctpManagement.addAssociation(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, 
					SERVER_ASSOCIATION_NAME, ipChannelType, null);
			}
			*/
			
			this.sctpManagement = new ManagementImpl("Server");
//			this.sctpManagement = new NettySctpManagementImpl("Server");
//			this.sctpManagement.setSingleThread(true);
			this.sctpManagement.start();
			this.sctpManagement.removeAllResourses();

			this.sctpManagement.setConnectDelay(10000);
			// 1. Create SCTP Server
			sctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, ipChannelType, null);

			// 2. Create SCTP Server Association
			sctpManagement
			.addServerAssociation(CLIENT_IP, CLIENT_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, ipChannelType);
//			serverAssociation.setAssociationListener(new ServerAssociationListener());
			
			// 3. Start Server
			sctpManagement.startServer(SERVER_NAME);

			logger.debug("Initialized SCTP Stack ....");
		}

		private void initM3UA() throws Exception {
			logger.debug("Initializing M3UA Stack ....");
			/*
			if (Configuration.Serverside == true ) {
				// server side configuration of M3UA
					this.M3UAMgmt = new M3UAManagementImpl("Server", null);
					this.M3UAMgmt.setTransportManagement(this.sctpManagement);
					this.M3UAMgmt.start();
					this.M3UAMgmt.removeAllResourses();

					// Step 1 : Create App Server

					RoutingContext rc = factory.createRoutingContext(new long[] { ROUTING_CONTEXT });
					TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
					this.M3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc,
							trafficModeType, 1, null);

					// Step 2 : Create ASP
					this.M3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

					// Step3 : Assign ASP to AS
					this.M3UAMgmt.assignAspToAs("RAS1", "RASP1");

					// Step 4: Add Route. Remote point code is 2
					this.M3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");
				
			}
			else {
			// client side configuration of M3UA
				this.M3UAMgmt = new M3UAManagementImpl("Server", null);
				this.M3UAMgmt.setTransportManagement(this.sctpManagement);
				this.M3UAMgmt.start();
				this.M3UAMgmt.removeAllResourses();

				// m3ua as create rc <rc> <ras-name>
				RoutingContext rc = factory.createRoutingContext(new long[] { ROUTING_CONTEXT });
				TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
				this.M3UAMgmt.createAs("RAS1", Functionality.IPSP, ExchangeType.SE, IPSPType.CLIENT, rc, 
					trafficModeType, 1, null);

				// Step 2 : Create ASP
				this.M3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);
				// Step3 : Assign ASP to AS
				AspImpl asp = this.M3UAMgmt.assignAspToAs("RAS1", "RASP1");
				// Step 4: Add Route. Remote point code is 2
				M3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");
			}
			*/
			this.M3UAMgmt = new M3UAManagementImpl("Server", null);
			this.M3UAMgmt.setTransportManagement(this.sctpManagement);
		 //this.serverM3UAMgmt.setDeliveryMessageThreadCount(DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
			this.M3UAMgmt.start();
			this.M3UAMgmt.removeAllResourses();

			// Step 1 : Create App Server

			RoutingContext rc = factory.createRoutingContext(new long[] { ROUTING_CONTEXT });
			TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
			this.M3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc,
					trafficModeType, 1, null);

			// Step 2 : Create ASP
			this.M3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

			// Step3 : Assign ASP to AS
			this.M3UAMgmt.assignAspToAs("RAS1", "RASP1");

			// Step 4: Add Route. Remote point code is 2
			this.M3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");

			logger.debug("Initialized M3UA Stack ....");
		}

	
	private void initSCCP() throws Exception {
		logger.debug("Initializing SCCP Stack ....");
		this.sccpStack = new SccpStackImpl("Server-SccpStack");
		this.sccpStack.setMtp3UserPart(1, this.M3UAMgmt);

		this.sccpStack.start();
		this.sccpStack.removeAllResourses();

		 this.sccpStack.getSccpResource().addRemoteSpc(1, CLIENT_SPC, 0, 0);
         this.sccpStack.getSccpResource().addRemoteSsn(1, CLIENT_SPC,  CLIENT_SSN, 0, false);

         this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, SERVER_SPC, NETWORK_INDICATOR, 0);
         this.sccpStack.getRouter().addMtp3Destination(1, 1, CLIENT_SPC, CLIENT_SPC, 0, 255, 255);
         // configure gtt address
         EncodingScheme ec = new BCDEvenEncodingScheme();
         GlobalTitle gt = null;
         gt = new GlobalTitle0100Impl("000", 0,  ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                 NatureOfAddress.INTERNATIONAL);

         SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, CLIENT_SPC, 0 );
         this.sccpStack.getRouter().addRoutingAddress(1, localAddress);
         
         
         gt = new GlobalTitle0100Impl("*", 0,  ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                 NatureOfAddress.INTERNATIONAL);
      SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, CLIENT_SPC, 0 );
         this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.LOCAL, pattern, "K", 1, -1, null, 0);

         gt = new GlobalTitle0100Impl("000", 0,  ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                 NatureOfAddress.INTERNATIONAL);
         SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, SERVER_SPC, 0 );
         this.sccpStack.getRouter().addRoutingAddress(2, remoteAddress);
         gt = new GlobalTitle0100Impl("*", 0,  ec, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,
                 NatureOfAddress.INTERNATIONAL);
       pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, SERVER_SPC, 0 );
         this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Undefined, OriginationType.REMOTE, pattern, "K", 2, -1, null, 0);

		
		
		logger.debug("Initialized SCCP Stack ....");
	}

	private void initTCAP() throws Exception {
		logger.debug("Initializing TCAP Stack ....");
		this.tcapStack = new TCAPStackImpl("Server-TcapStackMap", this.sccpStack.getSccpProvider(), SERVER_SSN);
		this.tcapStack.start();
		this.tcapStack.setDialogIdleTimeout(60000);
		this.tcapStack.setInvokeTimeout(30000);
		this.tcapStack.setMaxDialogs(2000);
		logger.debug("Initialized TCAP Stack ....");
	}

	private void initMAP() throws Exception {
		logger.debug("Initializing MAP Stack ....");
		this.mapStack = new MAPStackImpl("Server-MapStack", this.tcapStack.getProvider());
	
		this.mapProvider = this.mapStack.getMAPProvider();

		this.mapProvider.addMAPDialogListener( this);
		this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

		this.mapProvider.getMAPServiceSms().acivate();

		
		this.mapStack.start();
		logger.debug("Initialized MAP Stack ....");
	}

	
	
	protected void initializeStack(IpChannelType ipChannelType) throws Exception {

		this.initSCTP(ipChannelType);

		// Initialize M3UA first
		this.initM3UA();

		// Initialize SCCP
		this.initSCCP();

		this.initTCAP();
		// Initialize MAP
		this.initMAP();

		// 7. Start ASP
		M3UAMgmt.startAsp("RASP1");
		logger.debug("[[[[[[[[[[    Started HlrSimulator       ]]]]]]]]]]");

	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		System.out.println("*************************************");
		System.out.println("***          HlrSimulator           ***");
		System.out.println("*************************************");
		IpChannelType ipChannelType = IpChannelType.SCTP;
		if (args.length >= 1 && args[0].toLowerCase().equals("tcp"))
			ipChannelType = IpChannelType.TCP;

		final HlrSimulator hlrSimulator = new HlrSimulator();
		try {
			hlrSimulator.initializeStack(ipChannelType);
			Thread.sleep(1000000);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

    private void onMtRequest(SM_RP_DA da, SM_RP_OA oa, SmsSignalInfo si, MAPDialogSms curDialog) {

//        this.countMtFsmReq++;

        si.setGsm8Charset(isoCharset);
        String destImsi = null;
        if (da != null) {
            IMSI imsi = da.getIMSI();
            if (imsi != null)
                destImsi = imsi.getData();
        }
        AddressString serviceCentreAddr = null;

        if (oa != null) {
            serviceCentreAddr = oa.getServiceCentreAddressOA();
        }

        try {
            String msg = null;
            SmsDeliverTpdu dTpdu = null;
            if (si != null) {
                SmsTpdu tpdu = si.decodeTpdu(false);
                if (tpdu instanceof SmsDeliverTpdu) {
                    dTpdu = (SmsDeliverTpdu) tpdu;
                    UserData ud = dTpdu.getUserData();
                    if (ud != null) {
                        ud.decode();
                        msg = ud.getDecodedMessage();

                        UserDataHeader udh = ud.getDecodedUserDataHeader();
                        if (udh != null) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("[");
                            int i2 = 0;
                            for (byte b : udh.getEncodedData()) {
                                int i1 = (b & 0xFF);
                                if (i2 == 0)
                                    i2 = 1;
                                else
                                    sb.append(", ");
                                sb.append(i1);
                            }
                            sb.append("] ");
                            msg = sb.toString() + msg;
                        }
                    }
                }
            }

//            if (this.testerHost.getConfigurationData().getTestSmsClientConfigurationData().isOneNotificationFor100Dialogs()) {
  //              int i1 = countMtFsmReq / 100;
    //            if (countMtFsmReqNot < i1) {
      //              countMtFsmReqNot = i1;
    //                this.testerHost.sendNotif(SOURCE_NAME, "Rsvd: Ms messages: " + (countMtFsmReqNot * 100), "", Level.DEBUG);
        //        }
    //        } else {
         //       String uData = this.createMtData(curDialog, destImsi, dTpdu, serviceCentreAddr);
  //              this.testerHost.sendNotif(SOURCE_NAME, "Rcvd: mtReq: " + msg, uData, Level.DEBUG);
      //      }
        } catch (MAPException e) {
//            this.testerHost.sendNotif(SOURCE_NAME, "Exception when decoding MtForwardShortMessageRequest tpdu : " + e.getMessage(), e, Level.ERROR);
        }
    }
	
	@Override
	public void onDialogAccept(MAPDialog arg0, MAPExtensionContainer arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogClose(MAPDialog arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDialogDelimiter(MAPDialog mapDialog) {
		// TODO Auto-generated method stub
		logger.info("onDialogDelimiter:handle needSendClose/needSendSend");
	//	Boolean flag = (Boolean) mapDialog.getUserObject();
	//	 try {
	 //           if (flag != null) {
	  //          	mapDialog.send();
	   //         }
	    //        else {
	     //           mapDialog.close(true);
	      //      }
	    // } catch (Exception e) {
	    //       logger.error( "Exception when trying to send or close dialog" + e);
	     //       return;
	     //   }
		
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
	public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest ind) {
		// TODO Auto-generated method stub
		MAPDialogSms curDialog = ind.getMAPDialog();
		long invokeId = ind.getInvokeId();
        SM_RP_DA da = ind.getSM_RP_DA();
        SM_RP_OA oa = ind.getSM_RP_OA();
        SmsSignalInfo si = ind.getSM_RP_UI();

        this.onMtRequest(da, oa, si, curDialog);
        
        try {
        	curDialog.addMtForwardShortMessageResponse(invokeId,  null,  null);
        	this.needSendClose = true;
        }
        catch (MAPException e ) {
        	e.printStackTrace();
        }
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
	public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest ind) {
		MAPDialogSms curDialog = ind.getMAPDialog();
		logger.info("onSendRoutingInfoForSMRequest");
		 long invokeId = ind.getInvokeId();
         MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();
		 IMSI imsi = mapFactory.createIMSI("555667");

		 ISDNAddressString networkNodeNumber = mapFactory
				 		 .createISDNAddressString(AddressNature.international_number,
						 NumberingPlan.ISDN, "8786876");
        LocationInfoWithLMSI li = null;
//        li = mapProvider.getMAPParameterFactory().createLocationInfoWithLMSI(networkNodeNumber, null, null, false, null);
        li = mapFactory.createLocationInfoWithLMSI(networkNodeNumber, null, null, false, null);
        try {
			curDialog.addSendRoutingInfoForSMResponse(invokeId, imsi, li, null, null);
            curDialog.close(false);

		} catch (MAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        //this.needSendClose = true;
//        curDialog.setUserObject(true);
        
	}

	@Override
	public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse arg0) {
		// TODO Auto-generated method stub
		
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
		  public static final boolean Serverside = true;
		} 
	
	
}

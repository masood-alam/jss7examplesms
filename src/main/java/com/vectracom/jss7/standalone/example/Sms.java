package com.vectracom.jss7.standalone.example;

import java.io.Serializable;
import java.util.Date;

public class Sms implements Serializable {

	private int esmClass;
    private byte[] shortMessage;
    private String shortMessageText;
    private byte[] shortMessageBin;
	private Date submitDate;
	private int sourceAddrTon;
	private int sourceAddrNpi;
	private String sourceAddr;
	private int protocolId; // not present in data_sm

	
	/**
	 * Indicates Message Mode and Message Type
	 */
	public int getEsmClass() {
		return esmClass;
	}

	public void setEsmClass(int esmClass) {
		this.esmClass = esmClass;
	}

	/**
	 * Protocol Identifier SMPP parameter (TP-Protocol-Identifier files for GSM)
	 */
	public int getProtocolId() {
		return protocolId;
	}

	public void setProtocolId(int protocolId) {
		this.protocolId = protocolId;
	}
	
    /**
     * Message: text part
     */
    public String getShortMessageText() {
        return shortMessageText;
    }

    public void setShortMessageText(String shortMessageText) {
        this.shortMessageText = shortMessageText;
    }
	
    /**
     * Message: binary part (UDH for text message or all message for binary messages)
     */
    public byte[] getShortMessageBin() {
        return shortMessageBin;
    }

    public void setShortMessageBin(byte[] shortMessageBin) {
        this.shortMessageBin = shortMessageBin;
    }

	/**
	 * time when a message was received by SMSC
	 */
	public Date getSubmitDate() {
		return submitDate;
	}

	public void setSubmitDate(Date submitDate) {
		this.submitDate = submitDate;
	}

	/**
	 * smpp style type of number
	 */
	public int getSourceAddrTon() {
		return sourceAddrTon;
	}

	public void setSourceAddrTon(int sourceAddrTon) {
		this.sourceAddrTon = sourceAddrTon;
	}

	/**
	 * smpp style type of numbering plan indicator
	 */
	public int getSourceAddrNpi() {
		return sourceAddrNpi;
	}

	public void setSourceAddrNpi(int sourceAddrNpi) {
		this.sourceAddrNpi = sourceAddrNpi;
	}

	/**
	 * origination address
	 */
	public String getSourceAddr() {
		return sourceAddr;
	}

	public void setSourceAddr(String sourceAddr) {
		this.sourceAddr = sourceAddr;
	}
	
	
}

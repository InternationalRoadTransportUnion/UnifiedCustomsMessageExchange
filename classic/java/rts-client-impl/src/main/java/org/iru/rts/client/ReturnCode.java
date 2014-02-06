package org.iru.rts.client;

public enum ReturnCode {
	
	SUCCESS(2),
	UNCLASSIFIED_ERROR(1200),
	MISSING_MESSAGE_TAG_EXCEPTION(1210),
	UNKNOWN_MESSAGE_TAG_EXCEPTION(1211),
	INVALID_SUBSCRIBER_ID_EXCEPTION(1212),
	MISSING_ESESSIONKEY_EXCEPTION(1213),
	MISSING_PAYLOAD_EXCEPTION(1214),
	INVALID_MESSAGEID_EXCEPTION(1222),
	INVALID_INFORMATION_EXCHANGE_VERSION_EXCEPTION(1223),
	ESESSIONKEY_DECRYPTION_EXCEPTION(1230),
	PAYLOAD_DECRYPTION_EXCEPTION(1231),
	INVALID_QUERYID_EXCEPTION(1232),
	INVALID_PASSWORD_EXCEPTION(1233),
	INVALID_SENDTIME_EXCEPTION(1234),
	INVALID_ORIGINATOR_EXCEPTION(1236),
	INVALID_ORIGINTIME_EXCEPTION(1237),
	INVALID_QUERYTYPE_EXCEPTION(1239),
	INVALID_QUERYREASON_EXCEPTION(1240),
	INVALID_CARNETNUMBER_EXCEPTION(1241),
	INVALID_SENDERID_EXCEPTION(1242),
	DATABASE_QUERY_TIMEOUT_EXCEPTION(1250);
	
	private int code;
	
	private ReturnCode(int code) { this.code = code; }
	
	public int codeValue()  { return code; }
	
	public static ReturnCode getByCode(int code) {
		for (ReturnCode v : values())
			if (v.codeValue() == code)
				return v;
		throw new IllegalArgumentException("Unknown ReturnCode: "+code);
	}
}
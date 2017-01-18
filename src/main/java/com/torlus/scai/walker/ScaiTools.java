package com.torlus.scai.walker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.JwtBuilder;

public class ScaiTools {

	private static String prettifyItem(String item) {
		item = item.replaceAll("http://(.+):4567", "http://www.customer-bank.com");
		item = item.replaceAll("http://(.+):4568", "http://www.merchant-bank.com");
		item = item.replaceAll("http://(.+):4569", "http://www.mylittlewebstore.com");
		return item;
	}
	
	public static void prettify(Map<String, String> map) {
		String redirect = map.get("redirect");
		if (redirect != null) {
			map.put("redirect_label", prettifyItem(redirect));
		}
		String pp = map.get("pp");
		if (pp != null) {
			map.put("pp", prettifyItem(pp));
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Map<String,String> verifySigner(String msg, Certificate signer, Logger logger) throws Exception {

		String hdr = msg.substring(0, msg.indexOf('.'));
		String body = msg.substring(hdr.length() + 1);
		body = body.substring(0, body.indexOf('.'));
		byte hdrBytes[] = Base64.getDecoder().decode(hdr);
		byte bodyBytes[] = Base64.getDecoder().decode(body);
				
		Map<String,String> props = new HashMap<String, String>();
		ObjectMapper objectMapper = new ObjectMapper();
		props = objectMapper.readValue(hdrBytes, HashMap.class);
		
		String certURI = props.get("x5u");
		logger.info("verifiySigner: fetching @x5u " + certURI);
		HttpGet get = new HttpGet(certURI);
		HttpClient cli = HttpClients.createDefault();
		HttpResponse res = cli.execute(get);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        res.getEntity().writeTo(bos);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate issuerCert = cf.generateCertificate(new ByteArrayInputStream(bos.toByteArray()));

        issuerCert.verify(signer.getPublicKey());
		props = objectMapper.readValue(bodyBytes, HashMap.class);
		
		return props;
	}
	
	public static void embed(JwtBuilder builder, String msg) {
		String hdr = msg.substring(0, msg.indexOf('.'));
		String body = msg.substring(hdr.length() + 1);
		body = body.substring(0, body.indexOf('.'));
		String sig = msg.substring(msg.lastIndexOf('.') + 1);

		// builder.claim("scai_inner_header", hdr);
		// builder.claim("scai_inner_body", body);
		// builder.claim("scai_inner_signature", sig);
		builder.claim("scai_inner", msg);
	}
	
	public static String extractBody(Map<String,String> props) {
		String msg = props.get("scai_inner");
		String hdr = msg.substring(0, msg.indexOf('.'));
		String body = msg.substring(hdr.length() + 1);
		body = body.substring(0, body.indexOf('.'));
		return body;
	}
	
	private static void indent(StringBuilder sb, int count) {
		while(count-- > 0)
			sb.append("  ");
	}
	
	public static String prettyPrint(String msg) throws Exception {
		StringBuilder sb = new StringBuilder();
		prettyPrint(msg, 0, sb);
		return sb.toString();
	}
	
	@SuppressWarnings("unchecked")
	public static void prettyPrint(String msg, int tab, StringBuilder sb) throws Exception {
		String hdr = msg.substring(0, msg.indexOf('.'));
		String body = msg.substring(hdr.length() + 1);
		int n = body.indexOf('.');
		if (n > 0)
			body = body.substring(0, body.indexOf('.'));
		byte hdrBytes[] = Base64.getDecoder().decode(hdr);
		byte bodyBytes[] = Base64.getDecoder().decode(body);

		Map<String,String> props = new HashMap<String, String>();
		ObjectMapper objectMapper = new ObjectMapper();
		props = objectMapper.readValue(hdrBytes, HashMap.class);

		indent(sb, tab); sb.append("<header> {\n");
		for(String p : props.keySet()) {
			String v = props.get(p);
			indent(sb, tab + 1);
			sb.append("\"" + p + "\":\"" + v + "\",\n");
		}
		sb.setLength(sb.length() - 2);
		sb.append('\n');
		indent(sb, tab); sb.append("}\n");
		indent(sb, tab); sb.append(".<body> {\n");
		props = objectMapper.readValue(bodyBytes, HashMap.class);
		boolean embed = false;
		for(String p : props.keySet()) {
			Object o = props.get(p);
			String v = o.toString();
			if (p.startsWith("scai_inner")) {
				embed = true;
			} else {
				indent(sb, tab + 1);
				sb.append("\"" + p + "\":\"" + v + "\",\n");
			}
		}
		if (embed) {
			prettyPrint(props.get("scai_inner"), tab + 1, sb);
		} else {
			sb.setLength(sb.length() - 2);
			sb.append('\n');
		}
		indent(sb, tab); sb.append("}\n");
		if (n > 0) {
			indent(sb, tab); sb.append(".<signature>\n");			
		}
	}
}

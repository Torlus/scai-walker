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

public class SCAI {

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

		builder.claim("scai_inner_header", hdr);
		builder.claim("scai_inner_body", body);
		builder.claim("scai_inner_signature", sig);
	}
	
}

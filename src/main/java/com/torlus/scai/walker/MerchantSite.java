package com.torlus.scai.walker;

import static spark.Spark.port;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import spark.ExceptionHandler;
import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.template.mustache.MustacheTemplateEngine;

import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.post;


public class MerchantSite {
	
	private static final Logger logger = LoggerFactory.getLogger(Bank.class);

	private static final MustacheTemplateEngine templateEngine = new MustacheTemplateEngine();

	public static void main(String args[]) throws Exception {
		final int port = 4569;
		port(port);

		String keystore = "merchant-api-key";
		String endpoint = "http://localhost:4568/scai/";
		String merchant = "8332b60f-e5e0-4d9d-a0a1-504490a72983";
		
		SignatureAlgorithm alg = SignatureAlgorithm.RS256;
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(new File(keystore + ".p12")), "scai".toCharArray());
		Certificate cert = ks.getCertificate(keystore);
		RSAPrivateCrtKey key = (RSAPrivateCrtKey)ks.getKey(keystore, "scai".toCharArray());
		
		logger.info("cert:" + Base64.getEncoder().encodeToString(cert.getEncoded()));
		logger.info(" key:" + Base64.getEncoder().encodeToString(key.getEncoded()));
		
		get("/", (req, res) -> {
			Map<String, String> map = new HashMap<>();
			map.put("timestamp", new Date().toString());
			map.put("id", UUID.randomUUID().toString());
			map.put("latest", "http://localhost:4567/scai/");
			map.put("callback", "http://localhost:" + port + "/scai-response");
			return new ModelAndView(map, "merchant-index.mustache");
		}, templateEngine);
		
		post("/scai-request", (req, res) -> {
			String remote = req.queryParams("scai_endpoint");
			String id = req.queryParams("scai_id");
			Date now = new Date();
			JwtBuilder builder = Jwts.builder()
					.setHeaderParam("x5u", endpoint + "identities/" + merchant + "/pub")
					.setIssuer(endpoint + "identities/" + merchant)
					.setIssuedAt(now)
					.setSubject("payment-request")
					.setAudience(remote)
					.signWith(alg, key);
			builder.claim("scai_id", req.queryParams("scai_id"));			
			builder.claim("scai_amount", req.queryParams("scai_amount"));
			builder.claim("scai_callback", req.queryParams("scai_callback"));
			String jwt = builder.compact();
			String body = jwt.substring(jwt.indexOf('.') + 1, jwt.lastIndexOf('.'));
			logger.info(new String(Base64.getDecoder().decode(body)));

			Map<String, String> map = new HashMap<>();
			map.put("jwt", jwt);
			map.put("pp", SCAI.prettyPrint(jwt));
			map.put("redirect", endpoint + "inbox");
			return new ModelAndView(map, "redirect.mustache");
		}, templateEngine);
		
		post("/scai-response", (request, response) -> {
			String msg = request.queryParams("jwt");

			Claims vcls = Jwts.parser().setSigningKey(key).parseClaimsJws(msg).getBody();
			logger.info("verifiedClaims:" + vcls.toString());
			Map<String, String> map = new HashMap<>();
			map.put("id", (String)vcls.get("scai_id"));
			map.put("amount", (String)vcls.get("scai_amount"));
			map.put("status", (String)vcls.get("scai_status"));
			StringBuilder sb = new StringBuilder();
			SCAI.prettyPrint(msg, 0, sb);
			map.put("jwt", sb.toString());
			return new ModelAndView(map, "merchant-callback.mustache");
		}, templateEngine);
		
		
		exception(Exception.class, new ExceptionHandler() {
			@Override
			public void handle(Exception exception, Request request, Response response) {
				exception.printStackTrace();
				response.body("Merchant Site Exception " + System.currentTimeMillis());
			}
		});

	}
}

package com.cryptotronix.jwt;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;

import javax.crypto.*;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.cryptotronix.jwt.DeviceRegistration;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemReader;

public class TestJWT {

	public static final String reg = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJFUlJPUjAwMDAwMDAwMCIsImlhdCI6MTQxOTM3MzQyNiwicHViS2V5IjoiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXp1cmtSVEVXYi95S0xDdU1qMTE1bzJocGpLdXNcbmxpVXBMV090NGRYUk5LOTlUVjJoSGhYOWtqbmUvbS9FWURmWWY0WXpPZnVmNWRjaGxLOTZiUUNrUGc9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tIiwic3ViIjoiMDAwMDAwMDAwMDAwMDAwMDAwIn0.MEYCIQCCvUOHdpxqfr9tkxaq7fgarV6jreBBcU-_Mk-1QSrsNAIhANGnOBx2yxOjecyxmJwQCQ09NqAqb-lRNqwulXGGZ46P";
	public static final String priv_pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEINFcCx7Un7LIG1Rqxs5IirsgglOvEUjP7lAcJfPYumrYoAoGCCqGSM49AwEHoUQDQgAEzurkRTEWb/yKLCuMj115o2hpjKusliUpLWOt4dXRNK99TV2hHhX9\nkjne/m/EYDfYf4YzOfuf5dchlK96bQCkPg==-----END EC PRIVATE KEY-----\n\0";
	
	public static void test() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, JOSEException,
			NoSuchProviderException {

		Security.addProvider(new BouncyCastleProvider());

		// Create the public and private EC keys
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("ECDSA",
				"BC");
		keyGenerator.initialize(ECNamedCurveTable.getParameterSpec("P-256"));
		KeyPair keyPair = keyGenerator.generateKeyPair();

		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		
		System.out.println(DeviceRegistration.toPublicJWK(publicKey).toJSONString());

		// Create the EC signer
		JWSSigner signer = new ECDSASigner(privateKey.getS());

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date());
		claimsSet.setIssuer("https://c2id.com");

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256),
				claimsSet);

		// Compute the EC signature
		signedJWT.sign(signer);

		// Serialize the JWS to compact form
		String s = signedJWT.serialize();

		// The recipient must create a verifier with the public 'x' and 'y' EC
		// params
		BigInteger x = publicKey.getW().getAffineX();
		BigInteger y = publicKey.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		// Verify the EC signature
		// assertTrue("ES256 signature verified", signedJWT.verify(verifier));
		if (signedJWT.verify(verifier)) {
			System.out.println("Yeah!");
		}

		// Retrieve the JWT claims
		// assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
	}

	public static void main(String[] args)  {

		try {
			test();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
				| NoSuchProviderException | JOSEException e1) {
			e1.printStackTrace();
		}
		
		
		try {
			DeviceRegistration dr = new DeviceRegistration(reg);
		} catch (Exception e) {
			e.printStackTrace();
		}

//		JWT jwt = null;
//
//		try {
//			jwt = JWTParser.parse(reg);
//		} catch (ParseException e) {
//			// Invalid JWT encoding
//			System.out.println("oh no!");
//		}
//
//		if (jwt instanceof SignedJWT) {
//			SignedJWT jws = (SignedJWT) jwt;
//
//			PemReader pr = new PemReader(new StringReader(jws.getJWTClaimsSet()
//					.getAllClaims().get("pubKey").toString()));
//			byte[] b = pr.readPemObject().getContent();
//
//			X509EncodedKeySpec spec = new X509EncodedKeySpec(b);
//			KeyFactory factory = KeyFactory.getInstance("ECDSA");
//			ECPublicKey pub = (ECPublicKey) factory.generatePublic(spec);
//			
//			
//			KeyFactory factory2 = KeyFactory.getInstance("EC");
//			PemReader ppr = new PemReader(new StringReader(priv_pem));
//			byte[] br = ppr.readPemObject().getContent();
//			PKCS8EncodedKeySpec spec_priv = new PKCS8EncodedKeySpec(br);
//			ECPrivateKey priv = (ECPrivateKey) factory2.generatePrivate(spec_priv);
//			
//
//			BigInteger x = pub.getW().getAffineX();
//			BigInteger y = pub.getW().getAffineY();
//			JWSVerifier verifier = new ECDSAVerifier(x, y);
//
//			System.out.println(jws.serialize());
//			
//			System.out.println(jws.getHeader().toString());
//			
//			if (jws.verify(verifier))
//				System.out.println("Booya");
//			else
//				System.out.println("Say what!");
//
//			System.out.println(pub);
//
//			System.out.println(jwt.getJWTClaimsSet().getIssuer());
//			System.out.println(jwt.getJWTClaimsSet());
//		}

	}

}

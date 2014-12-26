package com.cryptotronix.jwt;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

public class DeviceRegistration {

	protected SignedJWT jwt;
	protected ECPublicKey pub;

	public DeviceRegistration(String encodedSignedJWT) throws ParseException,
			IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			SignatureException {

		this.jwt = (SignedJWT) JWTParser.parse(encodedSignedJWT);

		this.pub = (ECPublicKey) this.verify(this.jwt);

	}

	public PublicKey verify(SignedJWT jws) throws ParseException, IOException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			SignatureException {

		PemReader pr = new PemReader(new StringReader(jws.getJWTClaimsSet()
				.getAllClaims().get("pubKey").toString()));
		byte[] b = pr.readPemObject().getContent();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(b);
		KeyFactory factory = KeyFactory.getInstance("ECDSA");
		ECPublicKey pub = (ECPublicKey) factory.generatePublic(spec);

		pr.close();

		BigInteger x = pub.getW().getAffineX();
		BigInteger y = pub.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		try {
			if (!jwt.verify(verifier))
				throw new SignatureException("ECDSA Signature Failed");
		} catch (JOSEException e) {
			throw new SignatureException(e.toString());
		}

		return pub;

	}

	public static KeyPair createKeyPair() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		// Create the public and private EC keys
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("ECDSA",
				"BC");
		keyGenerator.initialize(ECNamedCurveTable.getParameterSpec("P-256"));
		return keyGenerator.generateKeyPair();

	}
	
	public static JWK toPublicJWK(ECPublicKey key){		
		return new ECKey(ECKey.Curve.P_256,key, KeyUse.SIGNATURE, null, JWSAlgorithm.ES256, null, null, null, null);	
	}
	
	public static JWK toPrivateJWK(ECPrivateKey key){
		return null;
		
	}

	public void createRegistrationData() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException,
			JOSEException {
		
		KeyPair keyPair = this.createKeyPair();

		this.pub = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		this.createRegistrationData(privateKey);
	}

	public JWTClaimsSet buildClaims(ECPublicKey pub) {
		JWTClaimsSet claimsSet = new JWTClaimsSet();

		StringWriter textWriter = new StringWriter();

		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date());
		claimsSet.setIssuer("https://c2id.com");

		return claimsSet;
	}

	protected void createRegistrationData(ECPrivateKey priv, ECPublicKey pub)
			throws JOSEException {
		// Create the EC signer
		JWSSigner signer = new ECDSASigner(priv.getS());

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = this.buildClaims(pub);

		this.jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);

		// Compute the EC signature
		this.jwt.sign(signer);

		// The recipient must create a verifier with the public 'x' and 'y' EC
		// params
		BigInteger x = this.pub.getW().getAffineX();
		BigInteger y = this.pub.getW().getAffineY();
		JWSVerifier verifier = new ECDSAVerifier(x, y);

		// Verify the EC signature
		// assertTrue("ES256 signature verified", signedJWT.verify(verifier));
		if (this.jwt.verify(verifier)) {
			System.out.println("Yeah!");
		}
	}

	public String toString() {
		return this.jwt.serialize();
	}

	public PublicKey getPublicKey() {
		return this.pub;
	}

}

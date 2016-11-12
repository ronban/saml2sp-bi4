/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.loves.sapidm.bi4;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PUT;
import javax.ws.rs.core.MediaType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCredentialResolverFactory;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * REST Web Service
 *
 * @author roney
 */
@Path("sso")
public class SamlResource {

    @Context
    private UriInfo context;

    /**
     * Creates a new instance of SamlResource
     */
    public SamlResource() {
    }

    /**
     * Retrieves representation of an instance of
     * com.loves.sapidm.bi4.SamlResource
     *
     * @return an instance of java.lang.String
     */
    @GET
    @Produces(MediaType.APPLICATION_XML)
    public String getXml() {
        //TODO return proper representation object
        return "<test>test</test>";
    }

    @POST
    @Consumes({MediaType.APPLICATION_XML})
    @Produces(MediaType.APPLICATION_XML)
    public String readSaml(@Context HttpServletRequest request, InputStream requestBody) throws IOException, Base64DecodingException, ParserConfigurationException, SAXException, UnmarshallingException, ValidationException, SecurityException, MetadataProviderException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(requestBody));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line);
        }
        System.out.println(out.toString());   //Prints the string content read from input stream

        //Process SAML Response
        String responseMessage = request.getParameter("SAMLResponse");

        byte[] base64DecodedResponse = Base64.decodeBase64(responseMessage);

        //Unmarshalling reponse
        ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = docBuilder.parse(is);
        Element element = document.getDocumentElement();

        //Unmarshalling the element
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject responseXmlObj = unmarshaller.unmarshall(element);

        Response response = (Response) responseXmlObj;

        Assertion assertion = response.getAssertions().get(0);

        String subject = assertion.getSubject().getNameID().getValue();

        String issuer = assertion.getIssuer().getValue();

        String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();

        String statusCode = response.getStatus().getStatusCode().getValue();
        
        
        boolean validation = validateReponse(response);
        
        if (validation){
            //forward to BOM application with issuer, subject, status and audience. 
        }
        else{
            //return error;
            
        }
        

        return out.toString();
    }

    

    private boolean validateReponse(Response response) {

        try {
            Signature sig = response.getSignature();
            InputStream metaDataInputStream = new FileInputStream("path/to/meta/data");

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document metaDataDocument = builder.parse(metaDataInputStream);
            Element metadataRoot = metaDataDocument.getDocumentElement();
            metaDataInputStream.close();

            DOMMetadataProvider idpMetadataProvider = new DOMMetadataProvider(metadataRoot);
            idpMetadataProvider.setRequireValidMetadata(true);
            idpMetadataProvider.setParserPool(new BasicParserPool());
            idpMetadataProvider.initialize();
            
            MetadataCredentialResolverFactory credentialResolverFactory = MetadataCredentialResolverFactory.getFactory();

            MetadataCredentialResolver credentialResolver = credentialResolverFactory.getInstance(idpMetadataProvider);

            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
            criteriaSet.add(new EntityIDCriteria("IPDEntityId"));

            X509Credential credential = (X509Credential) credentialResolver.resolveSingle(criteriaSet);

            SignatureValidator validator = new SignatureValidator(credential);
            validator.validate(sig);
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }

}

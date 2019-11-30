package saml.saml;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

/**
 * Hello world!
 *
 */
public class ADFSSAMLResponseValidator 
{				
	private static ADFSSAMLResponseValidator validator;
	
	private FileBackedHTTPMetadataResolver metadataResolver;
	
	private UnmarshallerFactory unmarshallerFactory;
	
	private DocumentBuilder docBuilder;
	
	private Properties properties = new Properties();
	
    private ADFSSAMLResponseValidator() throws FileNotFoundException, IOException
    {
    	
    	System.out.println("Initialising the ADFSSAMLResponseValidator");
    	
    	properties.load(new FileInputStream("./adfs.properties"));

    	try {
        	System.out.println("Initialising the OpenSAML InitializationService");
    		
			InitializationService.initialize();
			
			System.out.println("Finished initializing the InitializationService");

	    	HttpClient httpClient = HttpClientBuilder.create().build();
	    	
	    	metadataResolver = new FileBackedHTTPMetadataResolver(httpClient, properties.getProperty("federationUrl"), properties.getProperty("metadataCachePath"));
	    	metadataResolver.setId("123");
	    	BasicParserPool pp = new BasicParserPool();
	    	pp.initialize();
	    	
	    	metadataResolver.setParserPool(pp);
	    	
	    	System.out.println("Initialising the OpenSAML FileBackedHTTPMetadataResolver");
	    	metadataResolver.initialize();
	    	System.out.println("Finished initialising the OpenSAML FileBackedHTTPMetadataResolver");
	    	
	    	DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        	documentBuilderFactory.setNamespaceAware(true);
        	docBuilder = documentBuilderFactory.newDocumentBuilder();
        	
        	unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        	
        	System.out.println("Finished initialising the ADFSSAMLResponseValidator");
        		    	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	 	
    }
    
    public static ADFSSAMLResponseValidator GetInstance() throws FileNotFoundException, IOException {
    	if (validator == null) {
    		validator = new ADFSSAMLResponseValidator();
    	}
    	
    	return validator;
    }
    
    public boolean ValidateSAMLResponse(String SAMLResponse) {

    	try {
    		
    		System.out.println("Parsing the SAMLResponse input:");
    		System.out.println(SAMLResponse);
        	Document document = docBuilder.parse(new ByteArrayInputStream(SAMLResponse.getBytes()));
        	Element element = document.getDocumentElement();
        	Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        	
        	System.out.println("Unmarshalling the SAMLResponse");
        	XMLObject responseXmlObj = unmarshaller.unmarshall(element);
        	        	
        	Response response = (Response) responseXmlObj;
        	
        	Assertion ass = response.getAssertions().get(0);
        	
        	response.getAssertions().get(0).getDOM().setIdAttribute("ID", true);

	    	CriteriaSet cs = new CriteriaSet( new EntityIdCriterion(properties.getProperty("trustEntity")));        	
	    	System.out.println("Retrieving Identity Provider metadata");
	    	Iterable<EntityDescriptor> result = metadataResolver.resolve(cs);
	    	
	    	System.out.println("Finding match for public key in SAML response");
        	for (EntityDescriptor ed: result) {
        		for (KeyDescriptor kd: ed.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors()) {
        			for(X509Data xd: kd.getKeyInfo().getX509Datas()) {
        				for(X509Certificate xc: xd.getX509Certificates()) {
        					        					
        					if(xc.getValue() == ass.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue()) {
        						System.out.println("Found a public key match between SAMLResponse and metadata");
        						
        						X509Certificate cf = ass.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        						
        						String lexicalXSDBase64Binary = cf.getValue();
        						byte[] decodedString = Base64.getDecoder().decode(new String(lexicalXSDBase64Binary).getBytes("UTF-8"));
        						
        						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        						java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedString));
        		                
        						BasicX509Credential cred = new BasicX509Credential(cert);
        						
        						System.out.println("Validating SAMLResponse with public key");
        						
        						SignatureValidator.validate(response.getAssertions().get(0).getSignature(), cred);
        						
        						System.out.println("SAMLResponse successfully validated with public key");
        						
        						return true;
        					}
        				}
        			}
        		}
        	}
        	
        	System.out.println("Unable to find matching public key for SAMLResponse");
        	
        	return false;
        	
        } catch (Exception e) {
        	e.printStackTrace();
        	return false;
        }
    }
    
   
}

package com.kineticdata.bridgehub.adapter.footprints;

import com.kineticdata.bridgehub.adapter.BridgeAdapter;
import com.kineticdata.bridgehub.adapter.BridgeError;
import com.kineticdata.bridgehub.adapter.BridgeRequest;
import com.kineticdata.bridgehub.adapter.BridgeUtils;
import com.kineticdata.bridgehub.adapter.Count;
import com.kineticdata.bridgehub.adapter.Record;
import com.kineticdata.bridgehub.adapter.RecordList;
import com.kineticdata.commons.v1.config.ConfigurableProperty;
import com.kineticdata.commons.v1.config.ConfigurablePropertyMap;
import java.io.IOException;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.slf4j.LoggerFactory;

public class FootprintsAdapter implements BridgeAdapter {
    /*----------------------------------------------------------------------------------------------
     * PROPERTIES
     *--------------------------------------------------------------------------------------------*/

    /** Defines the adapter display name */
    public static final String NAME = "Footprints Bridge";

    /** Defines the logger */
    protected static final org.slf4j.Logger logger = LoggerFactory.getLogger(FootprintsAdapter.class);

    /** Adapter version constant. */
    public static String VERSION;
    /** Load the properties version from the version.properties file. */
    static {
        try {
            java.util.Properties properties = new java.util.Properties();
            properties.load(FootprintsAdapter.class.getResourceAsStream("/"+FootprintsAdapter.class.getName()+".version"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            logger.warn("Unable to load "+FootprintsAdapter.class.getName()+" version properties.", e);
            VERSION = "Unknown";
        }
    }

    /** Defines the collection of property names for the adapter */
    public static class Properties {
        public static final String PROPERTY_USERNAME = "Username";
        public static final String PROPERTY_PASSWORD = "Password";
        public static final String PROPERTY_BASE_URL = "Footprints Url";
    }

    private final ConfigurablePropertyMap properties = new ConfigurablePropertyMap(
        new ConfigurableProperty(Properties.PROPERTY_USERNAME).setIsRequired(true),
        new ConfigurableProperty(Properties.PROPERTY_PASSWORD).setIsRequired(true).setIsSensitive(true),
        new ConfigurableProperty(Properties.PROPERTY_BASE_URL).setIsRequired(true)
    );

    private String username;
    private String password;
    private String baseUrl;

    /*---------------------------------------------------------------------------------------------
     * SETUP METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public void initialize() throws BridgeError {
        this.username = properties.getValue(Properties.PROPERTY_USERNAME);
        this.password = properties.getValue(Properties.PROPERTY_PASSWORD);
        this.baseUrl = properties.getValue(Properties.PROPERTY_BASE_URL);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    @Override
    public void setProperties(Map<String,String> parameters) {
        properties.setValues(parameters);
    }

    @Override
    public ConfigurablePropertyMap getProperties() {
        return properties;
    }

    /**
     * Structures that are valid to use in the bridge
     */
    public static final List<String> VALID_STRUCTURES = Arrays.asList(new String[] {
        "Devices"
    });

    /*---------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public Count count(BridgeRequest request) throws BridgeError {
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        FootprintsQualificationParser parser = new FootprintsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

//        // Getting a different httpClient that will work with all SSL Certificates (for use in dev environments)
//        HttpClient client;
//        try {
//            client = getTestingHttpClient();
//        } catch (Exception e) {
//            throw new BridgeError(e);
//        }
//
        HttpClient client = HttpClients.createDefault();
        HttpResponse response;
        HttpGet get = new HttpGet(String.format("%s/api/1/devices?source=index&offset=0&query=%s",this.baseUrl,query));

        // Setting up the basic authentication and appending it to the HttpPost
        // object
        logger.trace("Appending the authorization header to the post call");
        String creds = this.username + ":" + this.password;
        byte[] basicAuthBytes = Base64.encodeBase64(creds.getBytes());
        get.setHeader("Authorization", "Basic " + new String(basicAuthBytes));

        String output = "";
        try {
            response = client.execute(get);
            HttpEntity entity = response.getEntity();
            output = EntityUtils.toString(entity);
            logger.trace("Request response code: " + response.getStatusLine().getStatusCode());
        }
        catch (IOException e) {
            logger.error(e.getMessage());
            throw new BridgeError("Unable to make a connection to Footprints.", e);
        }

        String countStr = "";
        JSONObject jsonOutput = (JSONObject)JSONValue.parse(output);
        for (Object key : jsonOutput.keySet()) {
            if (key.toString().equals("Total")) {
                countStr = jsonOutput.get("Total").toString();
            }
        }

        Long count = Long.valueOf(countStr);

        // Return the response
        return new Count(count);
    }

    @Override
    public Record retrieve(BridgeRequest request) throws BridgeError {
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        FootprintsQualificationParser parser = new FootprintsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());
        List<String> fields = request.getFields();

//        // Getting a different httpClient that will work with all SSL Certificates (for use in dev environments)
//        HttpClient client;
//        try {
//            client = getTestingHttpClient();
//        } catch (Exception e) {
//            throw new BridgeError(e);
//        }

        HttpClient client = HttpClients.createDefault();
        HttpResponse response;
        HttpGet get = new HttpGet(String.format("%s/api/1/devices?source=index&query=%s",this.baseUrl,query));

        // Setting up the basic authentication and appending it to the HttpPost
        // object
        logger.trace("Appending the authorization header to the post call");
        String creds = this.username + ":" + this.password;
        byte[] basicAuthBytes = Base64.encodeBase64(creds.getBytes());
        get.setHeader("Authorization", "Basic " + new String(basicAuthBytes));

        String output = "";
        try {
            response = client.execute(get);
            HttpEntity entity = response.getEntity();
            output = EntityUtils.toString(entity);
            logger.trace("Request response code: " + response.getStatusLine().getStatusCode());
        }
        catch (IOException e) {
            logger.error(e.getMessage());
            throw new BridgeError("Unable to make a connection to Footprints.", e);
        }

        Record record = new Record(null);
        JSONObject jsonOutput = (JSONObject)JSONValue.parse(output);
        if (jsonOutput != null && jsonOutput.containsKey("Total")) {
            if (!jsonOutput.get("Total").toString().equals("1")) {
                throw new BridgeError("Multiple results matched an expected single match query.");
            } else {
                for (Object o : jsonOutput.keySet()) {
                    String key = o.toString();
                    if (!key.equals("Date") && !key.equals("Status") && !key.equals("ErrorCode") && !key.equals("Total")) {
                        JSONObject deviceJson = (JSONObject)JSONValue.parse(jsonOutput.get(key).toString());
                        Map<String,Object> recordMap = new LinkedHashMap<String,Object>();
                        if (fields == null) { fields = new ArrayList( deviceJson.entrySet()); }
                        for (String field : fields) {
                            recordMap.put(field, deviceJson.get(field));
                        }
                        record = new Record(recordMap);
                            }
                        }
            }
        } else {
            record = null;
        }

        // Return the response
        return record;
    }

    @Override
    public RecordList search(BridgeRequest request) throws BridgeError {
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        FootprintsQualificationParser parser = new FootprintsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());
        List<String> fields = request.getFields();

//        // Getting a different httpClient that will work with all SSL Certificates (for use in dev environments)
//        HttpClient client;
//        try {
//            client = getTestingHttpClient();
//        } catch (Exception e) {
//            throw new BridgeError(e);
//        }

        HttpClient client = HttpClients.createDefault();
        HttpResponse response;
        HttpGet get = new HttpGet(String.format("%s/api/1/devices?source=index&query=%s&offset=0",this.baseUrl,query));

        // Setting up the basic authentication and appending it to the HttpPost
        // object
        logger.trace("Appending the authorization header to the post call");
        String creds = this.username + ":" + this.password;
        byte[] basicAuthBytes = Base64.encodeBase64(creds.getBytes());
        get.setHeader("Authorization", "Basic " + new String(basicAuthBytes));

        String output = "";
        try {
            response = client.execute(get);
            HttpEntity entity = response.getEntity();
            output = EntityUtils.toString(entity);
            logger.trace("Request response code: " + response.getStatusLine().getStatusCode());
        }
        catch (IOException e) {
            logger.error(e.getMessage());
            throw new BridgeError("Unable to make a connection to Footprints.", e);
        }

        String countStr = "";

        logger.debug("Search Output");
        logger.debug(output);

        ArrayList<Record> records = new ArrayList<Record>();
        JSONObject jsonOutput = (JSONObject)JSONValue.parse(output);
        if (jsonOutput != null && jsonOutput.containsKey("Total")) {
            for (Object o : jsonOutput.keySet()) {
                List record = new ArrayList();
                String key = o.toString();
                if (key.equals("Total")) {
                    countStr = jsonOutput.get("Total").toString();
                } else if (!key.equals("Date") && !key.equals("Status") && !key.equals("ErrorCode")) {
                    JSONObject deviceJson = (JSONObject)JSONValue.parse(jsonOutput.get(key).toString());
                    for (String field : request.getFields()) {
                        if (field.equals("deviceIT")) {
                            record.add(key);
                        } else if (deviceJson.containsKey(field)) {
                            record.add(deviceJson.get(field));
                        } else {
                            throw new BridgeError("There was an error attempting to retrieve the field '" + field + "'. Field does not exist.");
                        }
                    }
                    records.add((Record) record);
                }
            }
        } else {
            throw new BridgeError("There was an error retrieving results for the username '" + query + "'");
        }

        // Build up the default metadata
        Map<String,String> metadata = BridgeUtils.normalizePaginationMetadata(request.getMetadata());
        metadata.put("pageSize", String.valueOf("0"));
        metadata.put("pageNumber", String.valueOf("1"));
        metadata.put("offset", String.valueOf("0"));
        metadata.put("count", String.valueOf(countStr));
        metadata.put("size", String.valueOf(records.size()));

        // Return the response
        return new RecordList(fields, records, metadata);
    }

    // Both the getTrustingManger and getTestingHttpClient methods SHOULD NOT
    // BE USED IN A PRODUCTION ENVIRONMENT.
    private HttpClient getTestingHttpClient() throws NoSuchAlgorithmException, KeyManagementException {
        HttpClient httpclient = HttpClients.createDefault();

        X509HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, getTrustingManager(), new java.security.SecureRandom());

        SSLSocketFactory socketFactory = new SSLSocketFactory(sc);
        socketFactory.setHostnameVerifier(hostnameVerifier);
        Scheme sch = new Scheme("https", 443, socketFactory);
        httpclient.getConnectionManager().getSchemeRegistry().register(sch);

        return httpclient;
    }

    private TrustManager[] getTrustingManager() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                // Do nothing
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                // Do nothing
            }

        } };
        return trustAllCerts;
    }

}

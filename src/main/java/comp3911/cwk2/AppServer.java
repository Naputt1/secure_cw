package comp3911.cwk2;

import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;

public class AppServer {

    public static void main(String[] args) throws Exception {
        Log.setLog(new StdErrLog());

        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(AppServlet.class, "/*");

        Server server = new Server();

        //OLD HTTP CONNECTION
        //ServerConnector http = new ServerConnector(server);
        //http.setPort(8080);
        //server.addConnector(http);

        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        SslContextFactory.Server ssl = new SslContextFactory.Server();

        ssl.setKeyStorePath("keystore.jks");
        ssl.setKeyStorePassword("Jqx6weadu7qv");
        ssl.setKeyManagerPassword("Jqx6weadu7qv");

        ServerConnector https = new ServerConnector(
                server,
                new SslConnectionFactory(ssl, "http/1.1"),
                new HttpConnectionFactory(httpsConfig)
        );
        https.setPort(8443);
        server.addConnector(https);

        server.setHandler(handler);

        server.start();
        server.join();
    }
}

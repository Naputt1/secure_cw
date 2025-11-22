package comp3911.cwk2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;
import org.eclipse.jetty.servlets.CrossOriginFilter;
import org.eclipse.jetty.servlet.FilterHolder;
import javax.servlet.DispatcherType;
import java.util.EnumSet;

public class AppServer {

    public static void main(String[] args) throws Exception {
        Log.setLog(new StdErrLog());

        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(AppServlet.class, "/*");

        Server server = new Server(8080);
        server.setHandler(handler);

        server.start();
        server.join();
    }
}

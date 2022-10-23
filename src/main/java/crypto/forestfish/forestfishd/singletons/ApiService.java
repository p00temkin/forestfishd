package crypto.forestfish.forestfishd.singletons;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApiService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ApiService.class);
	private static ApiService single_instance = null;

	public ApiService(int port) {
		Server server = new Server(port);
		ServletContextHandler context = new ServletContextHandler();
		context.setContextPath("/");

		ServletHolder jerseyServlet =  context.addServlet(ServletContainer.class, "/*");
		jerseyServlet.setInitOrder(0);
		jerseyServlet.setInitParameter("jersey.config.server.provider.packages", "crypto.forestfish.forestfishd.api");

		HandlerCollection handlers = new HandlerCollection();
		handlers.setHandlers(new Handler[] { context, new DefaultHandler() });
		server.setHandler(handlers);

		try {
			server.start();
		} catch (Exception e) {
			LOGGER.error("Caught exception while starting REST service, exception: " + e.getMessage());
		}
	}
	
    public static ApiService getInstance(int port) {
        if (single_instance == null) single_instance = new ApiService(port);
        return single_instance;
    }
}

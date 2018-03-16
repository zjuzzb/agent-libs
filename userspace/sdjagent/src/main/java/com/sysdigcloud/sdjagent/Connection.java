package com.sysdigcloud.sdjagent;

import java.rmi.server.RMISocketFactory;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.management.*;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;


/**
 * RMIDirectSocketFactory creates a direct socket connection to the
 * specified port on the specified host.
 *
 * Copied from OpenJDK source to avoid issues after rename in Java 9
 * (it's now called sun.rmi.transport.tcp.TCPDirectSocketFactory,
 * which in turn fails on older JDK versions)
 */
class RMIDirectSocketFactory extends RMISocketFactory {

    public Socket createSocket(String host, int port) throws IOException
    {
        return new Socket(host, port);
    }

    public ServerSocket createServerSocket(int port) throws IOException
    {
        return new ServerSocket(port);
    }
}


public class Connection {
    private static final long CONNECTION_TIMEOUT = 10000;
    private static final long JMX_TIMEOUT = 20;
    private final static Logger LOGGER = Logger.getLogger(Connection.class.getName());
    private static final ThreadFactory DAEMON_THREAD_FACTORY = new DaemonThreadFactory();
    private JMXConnector connector;
    private MBeanServerConnection mbs;
    private HashMap<String, Object> env;
    private JMXServiceURL address;

    public Connection(String address) throws IOException
    {
        this.env = new HashMap<String, Object>();
        this.address = new JMXServiceURL(address);
        createConnection();
    }

    private static <T extends Throwable> T initCause(T wrapper, Throwable wrapped) {
        wrapper.initCause(wrapped);
        return wrapper;
    }

    public MBeanServerConnection getMbs()
    {
        return mbs;
    }

    protected void createConnection() throws IOException {
        this.env.put("attribute.remote.x.request.waiting.timeout", CONNECTION_TIMEOUT);
        // In file jdk/src/share/classes/com/sun/jndi/rmi/registry/RegistryContext.java
        // looks like a socketfactory is used to connect to RMI server and get the RMIServer stub
        // the default socket factory caches the connections and causes troubles because many containers
        // can have the same host ip (127.0.0.1 for example).
        // With this line we force to use this factory that just creates a new socket every time
        this.env.put("com.sun.jndi.rmi.factory.socket", new RMIDirectSocketFactory());
        closeConnector();
        LOGGER.fine("Connecting to: " + this.address);
        connector = connectWithTimeout(this.address, this.env);
        mbs = connector.getMBeanServerConnection();
    }

    /**
     * Connect to a MBean Server with a timeout
     * This code comes from this blog post:
     * https://weblogs.java.net/blog/emcmanus/archive/2007/05/making_a_jmx_co.html
     */
    JMXConnector connectWithTimeout(final JMXServiceURL url, final Map<String, Object> env) throws IOException {

        final BlockingQueue<Object> mailbox = new ArrayBlockingQueue<Object>(1);

        ExecutorService executor = Executors.newSingleThreadExecutor(DAEMON_THREAD_FACTORY);
        executor.submit(new Runnable() {
            public void run() {
                try {
                    JMXConnector connector = JMXConnectorFactory.connect(url, env);
                    if (!mailbox.offer(connector)) {
                        connector.close();
                    }
                } catch (Throwable t) {
                    mailbox.offer(t);
                }
            }
        });
        Object result;
        try {
            result = mailbox.poll(JMX_TIMEOUT, TimeUnit.SECONDS);
            if (result == null) {
                if (!mailbox.offer(""))
                    result = mailbox.take();
            }
        } catch (InterruptedException e) {
            throw initCause(new InterruptedIOException(e.getMessage()), e);
        } finally {
            executor.shutdown();
        }
        if (result == null) {
            LOGGER.warning("Connection timed out: " + url);
            throw new SocketTimeoutException("Connection timed out: " + url);
        }
        if (result instanceof JMXConnector) {
            return (JMXConnector) result;
        }
        try {
            throw (Throwable) result;
        } catch (Throwable e) {
            throw new IOException(e.toString(), e);
        }
    }

    public void closeConnector() {
        if (connector != null) {
            Disconnector.submit(connector);
            connector = null;
        }
    }

    @SuppressWarnings("unused")
    public boolean isAlive() {
        if (connector == null) {
            return false;
        }
        try {
            connector.getConnectionId();
        } catch (IOException e) { // the connection is closed or broken
            return false;
        }
        return true;
    }

    private static class DaemonThreadFactory implements ThreadFactory {
        public Thread newThread(Runnable r) {
            Thread t = Executors.defaultThreadFactory().newThread(r);
            t.setDaemon(true);
            return t;
        }
    }

    private static class CoreTimeoutThreadPoolExecutor extends ThreadPoolExecutor {
        private static final int POOL_SIZE = 10;
        private static final int THREAD_KEEPALIVE = 10;
        private static final int QUEUE_SIZE = 100;

        CoreTimeoutThreadPoolExecutor() {
            super(POOL_SIZE, POOL_SIZE, THREAD_KEEPALIVE, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(QUEUE_SIZE));
            allowCoreThreadTimeOut(true);
        }
    }

    private static class Disconnector {
        private static final ThreadPoolExecutor disconnectExecutor = new CoreTimeoutThreadPoolExecutor();

        static void submit(final JMXConnector connector) {
            try{
                disconnectExecutor.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            connector.close();
                        } catch (IOException e) {
                            // ignore
                        }
                    }
                });
            } catch (RejectedExecutionException e) {
                LOGGER.severe("JMX disconnection overload, terminating process");
                System.exit(1);
            }
        }
    }
}
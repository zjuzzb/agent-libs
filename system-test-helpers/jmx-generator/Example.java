import java.lang.management.ManagementFactory;
import javax.management.MBeanServer;
import javax.management.ObjectName;

class Simple implements SimpleMBean {
    private int count = 0;

    @Override
    public int getCount() {
        System.out.println("getCount(): " + count);
        return count;
    }

    @Override
    public void setCount(int newCount) {
        System.out.println("setCount(): " + newCount);
        count = newCount;
    }

    @Override
    public void increment() {
        ++count;
    }

}

public class Example {
    public static void main(String[] args) {
        try {
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            ObjectName name = new ObjectName("sysdig.example:type=example");
            SimpleMBean bean = new Simple();

            server.registerMBean(bean, name);

            for(;;) {
                bean.increment();
                Thread.sleep(1000);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}

package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;

import org.apache.commons.lang3.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import cic.cs.unb.ca.jnetpcap.worker.PostFlowData;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Cmd {


    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static TrafficFlowWorker mWorker;
    private static ExecutorService csvWriterThread;

    private static String networkInterfaceName;
    private static String outPath;

    private static void init() {
        csvWriterThread = Executors.newSingleThreadExecutor();
    }

    public static void main(String[] args) {
        boolean flag = true;

        if (args.length < 1) {
            logger.info("Please select network interface!");
            return;
        }

        networkInterfaceName = args[0];

        if (args.length < 2) {
            //logger.info("Please select output folder!");
            logger.info("Please select output url!");
            return;
        }

        outPath = args[1];

        init();

        while (flag) {
            try {
                startTrafficFlow(networkInterfaceName,outPath);
            } catch (Exception e) {
                logger.info(e.getMessage());
            }
        };
    }

    private static void startTrafficFlow(String nif,String outPath) {

        //String ifName = list.getSelectedValue().name();
        String ifName = nif;

        if (mWorker != null && !mWorker.isCancelled()) {
            return;
        }

        mWorker = new TrafficFlowWorker(ifName);
        mWorker.addPropertyChangeListener(event -> {
            TrafficFlowWorker task = (TrafficFlowWorker) event.getSource();
            if ("progress".equals(event.getPropertyName())) {
                logger.debug("progress");
            } else if (TrafficFlowWorker.PROPERTY_FLOW.equalsIgnoreCase(event.getPropertyName())) {
                //insertFlow((BasicFlow) event.getNewValue(),outPath);
                postFlowData((BasicFlow) event.getNewValue(),outPath);
            } else if ("state".equals(event.getPropertyName())) {
                switch (task.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            logger.debug("try");
                        } catch (CancellationException e) {

                            logger.info("Pcap stop listening");

                        }
                        break;
                }
            }
        });
        mWorker.execute();
    }

    private static void postFlowData(BasicFlow flow,String url) {
        List<String> flowStringList = new ArrayList<>();
        List<String[]> flowDataList = new ArrayList<>();
        String flowDump = flow.dumpFlowBasedFeaturesEx();
        flowStringList.add(flowDump);
        flowDataList.add(StringUtils.split(flowDump, ","));

        String header = FlowFeature.getHeader();
        /*String filename = LocalDate.now().toString() + FlowMgr.FLOW_SUFFIX;
        logger.info(header.toString());*/
        csvWriterThread.execute(new PostFlowData(header, flowStringList,url));
    }

/*
    private static void insertFlow(BasicFlow flow,String outPath) {
        List<String> flowStringList = new ArrayList<>();
        List<String[]> flowDataList = new ArrayList<>();
        String flowDump = flow.dumpFlowBasedFeaturesEx();
        flowStringList.add(flowDump);
        flowDataList.add(StringUtils.split(flowDump, ","));

        //write flows to csv file
        String header = FlowFeature.getHeader();

        String path = outPath;
        String filename = LocalDate.now().toString() + FlowMgr.FLOW_SUFFIX;
        logger.info(header.toString());
        //logger.info(header.getClass().toString());
        //logger.info(flowStringList.getClass().toString());
        //logger.info(String.valueOf(flowStringList.toString()));
        csvWriterThread.execute(new InsertCsvRow(header, flowStringList, path, filename));
        //logger.info(String.valueOf(flowStringList));
    }
*/

    static class FlowListener implements FlowGenListener {

        private String fileName;

        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {

            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            //InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, fileName + FlowMgr.FLOW_SUFFIX);
            PostFlowData.insert(FlowFeature.getHeader(), flowStringList, outPath);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName, cnt);

            System.out.print(console);
        }
    }

}

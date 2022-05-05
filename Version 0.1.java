

import com.adventnet.ds.query.*;
import com.adventnet.la.util.PersistenceDBUtil;
//import com.adventnet.la.util.TableNameConstants;
import com.adventnet.mfw.bean.BeanUtil;
import com.adventnet.persistence.DataAccess;
import com.adventnet.persistence.DataObject;
import com.adventnet.persistence.Persistence;
import com.adventnet.persistence.Row;
import com.adventnet.sa.server.util.CommonUtil;
import com.adventnet.swissqlapi.sql.functions.math.log;
import com.manageengine.ads.fw.db.util.DBUtil;
import com.manageengine.ela.server.archive.ArchiveConstants;
import com.manageengine.ela.server.archive.client.ArchiveOperationHandler;
import com.manageengine.ela.server.common.database.constants.TableNameConstants;
import com.manageengine.ela.server.correlation.common.constants.SharedConstants;
import com.manageengine.ela.server.correlation.core.builder.CorrelationBuilder;
import com.manageengine.ela.server.correlation.core.config.CorrConfigInfo;
import com.manageengine.ela.server.correlation.core.constants.CorrelationStatus;
import com.manageengine.ela.server.correlation.core.diagnostics.CorrelationDiagnosticsDataContainer;
import com.manageengine.ela.server.correlation.core.listener.CorrelationAuditListener;
import com.manageengine.ela.server.correlation.session.builder.ActivityRuleInitializer;
import com.manageengine.ela.server.correlation.session.info.ActivityProfileInfo;
import com.manageengine.ela.server.correlation.session.info.ActivityProviderInfo;
import com.manageengine.ela.server.correlation.session.util.ActivityUtil;
import com.manageengine.ela.server.correlation.util.CorrelationUtil;
import com.manageengine.ela.server.technician.audit.AuditEntry;
import com.manageengine.ela.server.archive.config.ExtendedArchiveConfiguration;
import com.manageengine.ela.server.common.response.BaseStatusCode;
import com.manageengine.ela.server.common.response.PredefinedStatusCodes;
import com.manageengine.ela.server.common.database.constants.TableNameConstants.*;
import com.manageengine.ela.server.common.response.ember.ResponseBuilder;
import org.json.JSONObject;

import java.io.*;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static com.adventnet.la.util.TableNameConstants.CORRELATION_ACTION_INFO;

public class PerformanceTool {
    static File directoryPath;
    static Long buildNumber,ESDatasize,CacheRecord,CachedRecordCount,scheduledReports,scheduledCompilance,scheduledImport;
    static String logsFolder="",TotalCPU="",RAM="",OSArch="",database="",ELAHeap="",ESHeap="",totalIndices="",Unassigned_Shards="",CachedRecord="",ATA="Disabled",Bundled="No",ArchivePath,ESPath,ESDataPath,ESDatasizeString,HardwareModel,HardwareManufacture,CacheRecordString;
    static String customAlert,CorrelatioAlert,ThreatAlert,ServerHome,CORRELATION_RETENTION,DB_RETENTION,ALERT_RETENTION,Archive_RETENTION="",WMIhosts,Syslogdevice,Win_agent,Linux_agent,Win_FIM,SQL,Machine="",VMReservation="NO",VMoverprovisioning="NO";
    static Map<Long,String> activeSessionRuleDetails,activeCorrRuleDetails,actionDetails;
    static int sessionActivityRulesize=0,corrRuleSize=0,corractionsize=0;
    static String fileList="",osname,Environment,LogForwarding;
    //static double winRate,sysRate;
    static JSONObject dbRetentionobj;
    static HashSet<String> logSources=new HashSet<String>();
    static HashSet<String> secApplication=new HashSet<String>();
    static HashSet<String> appResources=new HashSet<String>();
    static ArrayList<Double> winRate=new ArrayList<Double>();
    static ArrayList<Double> winTop10=new ArrayList<Double>();
    static ArrayList<Double> sysRate=new ArrayList<Double>();
    static ArrayList<Double> sysTop10=new ArrayList<Double>();
    static FileWriter outputWriter;
    static SelectQueryImpl selectQuery;


    public static void main(String[] args) throws Exception
    {
        try {
            //System.out.println("Persistance Started-----1");
            Thread.sleep(10000);
            Object standAlonePersObj = Class.forName("com.adventnet.persistence.StandAlonePersistence").newInstance(); //NO I18N
            Method method = Class.forName("com.adventnet.persistence.StandAlonePersistence").getDeclaredMethod("startServer"); //NO I18N
            //System.out.println("Persistance Started-----2");
            method.invoke(standAlonePersObj);
            Persistence pers = (Persistence) BeanUtil.lookup("Persistence");
            System.out.println("StandAlonePersistance Started");

            osname = System.getProperty("os.name","Windows");
            Environment = osname.startsWith("Win") ? "Windows" : "Linux";
            ServerHome = System.getProperty("server.home");
            logsFolder = System.getProperty("server.home") + File.separator + "logs";
            directoryPath = new File(logsFolder);
            fileList= ServerHome + File.separator + "logs\\PerformanceStats.csv";
            outputWriter = new FileWriter(fileList);

            getPerformanceStats();
            getCorrelationActivitystats();
            getScheduledstats();
            getDetailsfromCustomer();
            printPerformanceStats();
            if(Environment.equalsIgnoreCase("Windows"))
            {
                printPowershellcommand();
            }
        }
        catch (Exception e)
        {
            closeOutputWriter();
            System.out.println("Exception in getting Performance Tool : "+e);
        }
        finally{
            closeOutputWriter();
            System.exit(0);
        }
    }

    public static void closeOutputWriter() throws Exception
    {
        outputWriter.close();
    }

    public static void printPerformanceStats() throws Exception
    {
        TableList deviceInfoTableList = new TableList("Key","Value");

        //System.out.println("-----Build & device info-----");
        System.out.println("\nBuild & Device info");
        System.out.println("---------------------");
        //System.out.println(String.join("\u0332",("Build & device info").split("",-1)));

        deviceInfoTableList.addRow("BuildNumber",buildNumber.toString());
        deviceInfoTableList.addRow("WMIhosts",WMIhosts.toString());
        deviceInfoTableList.addRow("Syslogdevices",Syslogdevice);
        deviceInfoTableList.addRow("Win_agent",Win_agent);
        deviceInfoTableList.addRow("Linux_agent",Linux_agent);
        deviceInfoTableList.addRow("Win_FIM",Win_FIM);
        deviceInfoTableList.addRow("SQL",SQL);
        deviceInfoTableList.print();
//        System.out.println("\nBuildNumber : "+buildNumber);
//        System.out.println("WMIhosts : "+WMIhosts);
//        System.out.println("Syslogdevices : "+Syslogdevice);
//        System.out.println("Win_agent : "+Win_agent);
//        System.out.println("Linux_agent : "+Linux_agent);
//        System.out.println("Win_FIM : "+Win_FIM);
//        System.out.println("SQL : "+SQL);
        //System.out.println("\n-----LogSources info-----");
        System.out.println("\nLogSources Info");
        System.out.println("-----------------");
        //System.out.println(String.join("\u0332",("LogSources info").split("",-1)));
        TableList logSourcesTableList = new TableList("Key","Value");
        logSourcesTableList.addRow("Devices types",logSources.toString());
        logSourcesTableList.addRow("Security Application : ",secApplication.toString());
        logSourcesTableList.addRow("Appresources",appResources.toString());
        logSourcesTableList.print();
//        System.out.print("\nDevices types : ");
//        Iterator logSourcesItr = logSources.iterator();
//        while (logSourcesItr.hasNext()) {
//            System.out.print(logSourcesItr.next()+", ");
//        }
//        System.out.println();
//        System.out.print("Security Application : ");
//
//        //System.out.println("--------------------");
//        Iterator secApplicationItr = secApplication.iterator();
//        while (secApplicationItr.hasNext()) {
//            System.out.print(secApplicationItr.next()+", ");
//        }
//        System.out.println();
//        System.out.print("Appresources : ");
//        //System.out.println("--------------------");
//        Iterator AppresourcesItr = appResources.iterator();
//        while (AppresourcesItr.hasNext()) {
//            System.out.print(AppresourcesItr.next()+", ");
//        }
        System.out.println("\n\n----------------------System configuration----------------------");
        System.out.println("\nTotalCPU : "+TotalCPU+"\nRAM : "+(RAM !="" ? String.format("%.2f",(Double.parseDouble(RAM)/1024))+"GB" :null));
        System.out.println("\nOSArch : "+OSArch+"\nDatabase : "+database+"\nHardware Model : "+HardwareModel+"\nHardware Manufacturer : "+HardwareManufacture+"\nEnvironment : "+Environment);
        System.out.println("Machine :"+Machine+"\nVMReservation :"+VMReservation+"\nVMoverprovisioning :"+VMoverprovisioning);
        



        System.out.println("\n----------------------Product configuration----------------------");
        System.out.println("\nELA heap :"+ELAHeap+"mb "+"\nES heap :"+ESHeap);
        System.out.println("Retention Details : CORRELATION_RETENTION :"+CORRELATION_RETENTION+" DB_RETENTION :"+DB_RETENTION+" ALERT_RETENTION :"+ALERT_RETENTION+" Archive_RETENTION :"+Archive_RETENTION);
        System.out.println("CustomAlert :"+customAlert+" CorrelatioAlert :"+CorrelatioAlert+" ThreatAlert :"+ThreatAlert);
        System.out.println("scheduledReports :"+scheduledReports+" scheduledCompilance :"+scheduledCompilance+" scheduledImport :"+scheduledImport);
        System.out.println("ATA :"+ATA+"\nLog360 bundled :"+Bundled+"\nLogForwarding :"+LogForwarding);
        System.out.println("\n----------------------ES & Archive path----------------------");
        System.out.println("\nArchive Path : "+ArchivePath+"\nES Path : "+ESPath+"\nELA installation directory : "+ServerHome);
        System.out.println("\n----------------------ES related information----------------------");
        System.out.println("\nESDataPath : "+ESDataPath+"\nESDatasizeString"+ESDatasizeString);
        System.out.println("\nCachedRecordCount : "+CachedRecordCount+"\nCacheRecordFolderSize : "+CacheRecordString+"\nCachedRecord : "+CachedRecord.replaceAll(" \\|", ","));
        System.out.println("\nTotalIndices : "+totalIndices+"\nUnassigned_Shards : "+Unassigned_Shards.replaceAll(" \\|", ","));
        System.out.println("\n----------------------Correlation & Activity----------------------");
        System.out.println("\nCorrelation Rule Details :- \nTotal Count : "+corrRuleSize+"\nActive Rules Count : "+activeCorrRuleDetails.size()+"\nDetails : "+activeCorrRuleDetails);
        System.out.println("\nCorrelation Action Details :- \nTotal Count : "+corractionsize+"\nCount of Actions used by active rules : "+actionDetails.size()+"\nDetails : "+actionDetails);
        System.out.println("\nCorrelation Rule Details - Session Activity :- \nTotal Count : "+sessionActivityRulesize+"\nActive Rules Count : "+activeSessionRuleDetails.size()+"\nDetails : "+activeSessionRuleDetails);
        System.out.println("\n----------------------Logflow details----------------------");
        System.out.print("\nWindows Top 10 Session Rate : ");
        Iterator itrWinFlow = winTop10.iterator();
        while (itrWinFlow.hasNext()) {
            System.out.print(itrWinFlow.next()+", ");
        }
        System.out.print("\nSyslog Top 10 Session Rate : ");
        Iterator itrSysFlow = sysTop10.iterator();
        while (itrSysFlow.hasNext()) {
            System.out.print(itrSysFlow.next()+", ");
        }

        /*** Writing in file ***/
        outputWriter.write("----------------------Build & device info----------------------");
        outputWriter.write("\nBuildNumber : "+buildNumber);
        outputWriter.write("\nWMIhosts : "+WMIhosts);
        outputWriter.write("\nSyslogdevices : "+Syslogdevice);
        outputWriter.write("\nWin_agent : "+Win_agent);
        outputWriter.write("\nLinux_agent : "+Linux_agent);
        outputWriter.write("\nWin_FIM : "+Win_FIM);
        outputWriter.write("\nSQL : "+SQL);
        outputWriter.write("\n----------------------LogSources info----------------------");
        outputWriter.write("\nDevices  : ");
        Iterator logSourcesitrWriter = logSources.iterator();
        while (logSourcesitrWriter.hasNext()) {
            outputWriter.write(logSourcesitrWriter.next()+", ");
        }
        outputWriter.write("\nSecurity Application : ");
        //System.out.println("--------------------");
        Iterator secApplicationItrWriter = secApplication.iterator();
        while (secApplicationItrWriter.hasNext()) {
            outputWriter.write(secApplicationItrWriter.next()+", ");
        }
        outputWriter.write("\nAppresources : ");
        //System.out.println("--------------------");
        Iterator AppresourcesItrWriter = appResources.iterator();
        while (AppresourcesItrWriter.hasNext()) {
            outputWriter.write(AppresourcesItrWriter.next()+", ");
        }
        outputWriter.write("\n----------------------System Configuration----------------------");
        outputWriter.write("\nTotalCPU : "+TotalCPU+"\nRAM : "+(RAM !="" ? String.format("%.2f",(Double.parseDouble(RAM)/1024))+"GB" :null));
        outputWriter.write("\nOSArch : "+OSArch+"\nDatabase : "+database+"\nHardware Model : "+HardwareModel+"\nHardware Manufacturer : "+HardwareManufacture);
        outputWriter.write("\nMachine Type :"+Machine+" VMReservation :"+VMReservation+" VMoverprovisioning :"+VMoverprovisioning);
        outputWriter.write("\n----------------------Product Configuration----------------------");
        outputWriter.write("\nELA heap :"+ELAHeap+"mb "+"\nES heap :"+ESHeap);
        outputWriter.write("\nRetention Details : Correlation_retention :"+CORRELATION_RETENTION+" DB_retention :"+DB_RETENTION+" Alert_retention :"+ALERT_RETENTION+" Archive_retention :"+Archive_RETENTION);
        outputWriter.write("\nCustomAlert :"+customAlert+" CorrelatioAlert :"+CorrelatioAlert+" ThreatAlert :"+ThreatAlert);
        outputWriter.write("\nScheduledReports :"+scheduledReports+" scheduledCompilance :"+scheduledCompilance+" scheduledImport :"+scheduledImport);
        outputWriter.write("\nATA :"+ATA+"\nLog360 bundled : "+Bundled);
        outputWriter.write("\n----------------------ES & Archive path----------------------");
        outputWriter.write("\nArchive Path : "+ArchivePath+"\nES Path : "+ESPath+"\nELA installation directory : "+ServerHome);
        outputWriter.write("\n----------------------ES related information----------------------");
        outputWriter.write("\nESDataPath : "+ESDataPath+"\nESDatasize : "+ESDatasizeString);
        outputWriter.write("\nCachedRecordCount : "+CachedRecordCount+"\nCacheRecordSize : "+CacheRecordString+"\nCachedRecord : "+CachedRecord.replaceAll(" \\|", ","));
        outputWriter.write("\nTotalIndices : "+totalIndices+"\nUnassigned_Shards : "+Unassigned_Shards.replaceAll(" \\|", ","));
        outputWriter.write("\n----------------------Correlation & Activity----------------------");
        outputWriter.write("\nCorrelation Rule Details :- \nTotal Count : "+corrRuleSize+"\nActive Rules Count : "+activeCorrRuleDetails.size()+"\nDetails : "+activeCorrRuleDetails);
        outputWriter.write("\nCorrelation Action Details :- \nTotal Count : "+corractionsize+"\nCount of Actions used by active rules : "+actionDetails.size()+"\nDetails : "+actionDetails);
        outputWriter.write("\nCorrelation Rule Details - Session Activity :- \nTotal Count : "+sessionActivityRulesize+"\nActive Rules Count : "+activeSessionRuleDetails.size()+"\nDetails : "+activeSessionRuleDetails);
        outputWriter.write("\n----------------------Logflow details----------------------");
        outputWriter.write("\nWindows Top 10 Session Rate : ");
        Iterator itrWinFlow1 = winTop10.iterator();
        while (itrWinFlow1.hasNext()) {
            outputWriter.write(itrWinFlow1.next()+", ");
        }
        outputWriter.write("\nSyslog Top 10 Session Rate : ");
        Iterator itrSysFlow1 = sysTop10.iterator();
        while (itrSysFlow1.hasNext()) {
            outputWriter.write(itrSysFlow1.next()+", ");
        }

    }

    public static void getPerformanceStats() throws Exception
    {
        /*** Build Number ***/
        String buildFile = System.getProperty("server.home")+ File.separator+"troubleshooting"+File.separator +"build.properties"; //No I18N
        Properties buildProp = new Properties();
        try (FileInputStream inputStream = new FileInputStream(buildFile)) {
            buildProp.load(inputStream);
            buildNumber = Long.valueOf(buildProp.getProperty("buildnumber"));
        }
        catch(Exception e)
        {
            System.out.println("Exception in printBuildDeviceInfo : "+e);
            e.printStackTrace();
        }

        /*** Retention Details ***/

        dbRetentionobj = new JSONObject();
        try
        {
            CORRELATION_RETENTION = String.valueOf(CommonUtil.getSysConfiguration("CORRELATION_RETENTION_PERIOD")); //No I18N
            Criteria criteria = new Criteria(new Column(com.adventnet.la.util.TableNameConstants.DATA_MANAGEMENT_TIMING, "TIMER_NAME"), "SYS_DATA_WINDOW", QueryConstants.EQUAL);
            DataObject dobj = PersistenceDBUtil.getPersistence().get(com.adventnet.la.util.TableNameConstants.DATA_MANAGEMENT_TIMING, criteria);
            DB_RETENTION =  String.valueOf(dobj.getFirstRow(com.adventnet.la.util.TableNameConstants.DATA_MANAGEMENT_TIMING).get("TIMESTAMP")); //No I18N
            ALERT_RETENTION = String.valueOf(CommonUtil.getSysConfiguration("ALERT_RETENTION_PERIOD")); //No I18N
            JSONObject object = ArchiveOperationHandler.getArchiveSettings(null);
            Archive_RETENTION = object.getLong(ArchiveConstants.LOADED_ARCHIVE_RETENTION_TIME)+" "+object.getString(ArchiveConstants.LOADED_ARCHIVE_RETENTION_MODE);
        }
        catch(Exception e)
        {
            System.out.println("Exception getting Retention details : "+e);
        }

        /*** CPU , RAM , ELA Java heap , Archive & ES path , ***/
        String contents[] = directoryPath.list();
        for (int i = 0; i < contents.length; i++) {
            if (contents[i].startsWith("serverout")) {
                String serveroutPath = logsFolder + "\\" + contents[i];
                File sysEvtFile = new File(serveroutPath);
                Scanner winReader = new Scanner(sysEvtFile);
                int count = 0;
                while (winReader.hasNextLine()) {
                    String data = winReader.nextLine();
                    if (data.contains("LogCollector stats") && data.contains("Available cores")) {
                        String s1 = "Available cores\":";
                        int index11 = data.indexOf(s1);
                        int index12 = data.indexOf(",", index11);
                        TotalCPU = data.substring(index11 + s1.length(), index12);

                        String s2 = "Total RAM in MB\":";
                        int index21 = data.indexOf(s2);
                        int index22 = data.indexOf(",", index21);
                        RAM = data.substring(index21 + s2.length(), index22);

                        String s3 = "JVM Max Heap Size\":";
                        int index31 = data.indexOf(s3);
                        int index32 = data.indexOf(",", index31);
                        ELAHeap = data.substring(index31 + s3.length(), index32);

                        String s7 = "Archive Path\":";
                        int index71 = data.indexOf(s7);
                        int index72 = data.indexOf(",", index71);
                        ArchivePath = data.substring(index71 + s7.length(), index72);

                        String s4 = "ES Path\":";
                        int index41 = data.indexOf(s4);
                        int index42 = data.indexOf(",", index41);
                        ESPath = data.substring(index41 + s4.length(), index42);

                        ESPath = ESPath.replaceAll("\"", "");

                        String s5 = "Hardware Model\":";
                        int index51 = data.indexOf(s5);
                        int index52 = data.indexOf(",", index51);
                        HardwareModel = data.substring(index51 + s5.length(), index52);

                        String s6 = "Hardware Manufacturer\":\"";
                        int index61 = data.indexOf(s6);
                        int index62 = data.indexOf(",", index61);
                        HardwareManufacture = data.substring(index61 + s6.length(), index62);

                        String s8 = "Win Agent\":";
                        int index81 = data.indexOf(s8);
                        int index82 = data.indexOf(",", index81);
                        Win_agent=data.substring(index81 + s8.length(), index82);

                        String s9 = "Linux Agent\":";
                        int index91 = data.indexOf(s9);
                        int index92 = data.indexOf(",", index91);
                        Linux_agent=data.substring(index91 + s9.length(), index92);

                        String s10 = "Win FIM\":";
                        int index101 = data.indexOf(s10);
                        int index102 = data.indexOf(",", index101);
                        Win_FIM=data.substring(index101 + s10.length(), index102);

                        String s11 = "SQL\":";
                        int index111 = data.indexOf(s11);
                        int index112 = data.indexOf("}", index111);
                        SQL=data.substring(index111 + s11.length(), index112);

                        String s12 = "LogForwarding Enabled\":";
                        int index121 = data.indexOf(s12);
                        int index122 = data.indexOf("}", index121);
                        LogForwarding=data.substring(index121 + s12.length(), index122);


                    } else if (data.contains("Total Indices: ")) {
                        String s1 = "Total Indices: ";
                        int index11 = data.indexOf(s1);
                        int index12 = data.indexOf(",", index11);
                        totalIndices = totalIndices +data.substring(index11 + s1.length(), index12)+", ";

                        String s2 = "Unassigned Shards: ";
                        int index21 = data.indexOf(s2);
                        Unassigned_Shards+=data.substring(index21 + s2.length())+" ";
                        Unassigned_Shards = Unassigned_Shards.replaceAll("\\|", ",");


                    } else if (data.contains("cached record")) {
                        String s2 = "cached record count :";
                        int index21 = data.indexOf(s2);
                        CachedRecord = CachedRecord + " " + data.substring(index21 + s2.length());
                        CachedRecord = CachedRecord.replaceAll("\\|", ",");
                    } else if (data.contains("ThreatAnalyticsActionExecutor")) {
                        ATA = "Enabled";
                    } else if (data.contains("IS_BUNDLED for ManageEngine EventLog Analyzer")) {
                        if (data.contains("true")) {
                            Bundled = "yes";
                        }
                    } else if (data.contains("NotificationManager") && data.contains("Custom Alerts")) {
                        String s1 = "Custom Alerts ";
                        int index11 = data.indexOf(s1);
                        int index12 = data.indexOf(",", index11);
                        customAlert = data.substring(index11 + s1.length(), index12);

                        String s2 = "Correlation Alerts ";
                        int index21 = data.indexOf(s2);
                        int index22 = data.indexOf(",", index21);
                        CorrelatioAlert = data.substring(index21 + s2.length(), index22);

                        String s3 = "Threat Alerts ";
                        int index31 = data.indexOf(s3);
                        ThreatAlert = data.substring(index31 + s3.length());
                    }
                    else if(data.contains("New YML config") && data.contains("path.data"))
                    {
                        String s1 = "path.data=[";
                        int index11 = data.indexOf(s1);
                        int index12 = data.indexOf("]", index11);
                        ESDataPath = data.substring(index11 + s1.length(), index12);
                        //System.out.println("ESDataPath is "+ESDataPath);
                        File file1 = new File(ESDataPath);
                        try {
                            ESDatasize = getFolderSize(file1);
                            ESDatasizeString = String.valueOf(ESDatasize);
                        } catch (Exception e) {
                            System.out.println("Exception in ESDatasize");
                        }
                    }
                }
            }
        }
                    String str1 = logsFolder+"\\..\\ES\\CachedRecord";
                    File file2 = new File(str1);
                    try{
                        CacheRecord = getFolderSize(file2);
                        File[] files = file2.listFiles();
                        CachedRecordCount = Long.parseLong(String.valueOf(files.length));
                        CacheRecordString=String.valueOf(CacheRecord);
                    }
                    catch(Exception e)
                    {
                        System.out.println("Exception in CacheRecordsize");
                    }
        if(CacheRecord!=0)
        {
            CacheRecordString = String.format("%.2f",(Double.parseDouble(String.valueOf(CacheRecordString))/(1024*1024*1024)))+"GB";
        }
        if(ESDatasize!=0)
        {
            ESDatasizeString=String.format("%.2f",(Double.parseDouble(String.valueOf(ESDatasizeString))/(1024*1024*1024)))+"GB";
        }

        /*** OS Arch , database & Device information ***/
        for(int i=0; i<contents.length; i++)
        {
            if(contents[i].startsWith("SysEvtColLogs"))
            {
                String serveroutPath=logsFolder+"\\"+contents[i];
                File sysEvtFile = new File(serveroutPath);
                Scanner winReader = new Scanner(sysEvtFile);
                int count=0;
                while (winReader.hasNextLine())
                {
                    String data = winReader.nextLine();
                    if(data.contains("OS Architecture"))
                    {
                        String s1="OS Architecture : ";
                        int index11=data.indexOf(s1);
                        OSArch=data.substring(index11+s1.length());
                    }
                    else if(data.contains("Database"))
                    {
                        String s2="Database::";
                        int index21=data.indexOf(s2);
                        database=data.substring(index21+s2.length());
                    }

                    else if(data.contains("Total WMI hosts"))
                    {
                        String s2="Total WMI hosts : ";
                        int index21=data.indexOf(s2);
                        WMIhosts=data.substring(index21+s2.length());
                    }
                    else if(data.contains("Total Syslog hosts"))
                    {
                        String s2="Total Syslog hosts : ";
                        int index21=data.indexOf(s2);
                        Syslogdevice=data.substring(index21+s2.length());
                    }
                    else if(data.contains("Windows: Lifetime Count"))
                    {
                        try {
                            String s2 = "Session Rate = ";
                            int index21 = data.indexOf(s2);
                            Double dwin = Double.parseDouble(data.substring(index21 + s2.length()));
                            winRate.add(dwin);
                        }catch (Exception e)
                        {
                            System.out.println(e);
                        }
                    }
                    else if(data.contains("SysLogs: Lifetime Count"))
                    {
                        try {
                        String s2="Session Rate = ";
                        int index21=data.indexOf(s2);
                        Double dsys = Double.parseDouble(data.substring(index21 + s2.length()));
                        sysRate.add(dsys);
                    }catch (Exception e)
                    {
                        System.out.println(e);
                    }
                    }
                }
            }
        }
        /*** Top10 Win & Sys FLow ***/
        Collections.sort(winRate);
        if(winRate.size() > 0)
        winTop10 = new ArrayList<Double>(winRate.subList(winRate.size() -10, winRate.size()));
        Collections.sort(sysRate);
        if(sysRate.size() > 0)
        sysTop10 = new ArrayList<Double>(sysRate.subList(sysRate.size() -10, sysRate.size()));


        /*** ES heap ***/
        for(int i=0; i<contents.length; i++) {
            if (contents[i].startsWith("serverout")) {
                String serveroutPath = logsFolder + "\\" + contents[i];
                File sysEvtFile = new File(serveroutPath);
                Scanner winReader = new Scanner(sysEvtFile);
                int count = 0;
                while (winReader.hasNextLine()) {
                    String data = winReader.nextLine();
                    if (data.contains("ES stats for the past hour")) {
                        String s1 = "\"HEAP_COMMITTED\":\"";
                        int index11 = data.indexOf(s1);
                        int index12 = data.indexOf(",", index11);
                        ESHeap = data.substring(index11 + s1.length(), index12);
                    }
                }
            }
        }
       // System.out.println("ESHeap :"+ESHeap);

        /*** Logsources :  Devicetype ,Security Application,Application ***/

        /** Devicetype **/
        selectQuery = new SelectQueryImpl(Table.getTable(TableNameConstants.DEVICEDETAILS));
        selectQuery.addSelectColumn(new Column(TableNameConstants.DEVICEDETAILS, "*"));
        DataObject dataObject = DataAccess.get(selectQuery);
        if (!dataObject.isEmpty()) {
            Iterator deviceDetailsIterator = dataObject.getRows(TableNameConstants.DEVICEDETAILS);
            while (deviceDetailsIterator.hasNext()) {
                Row deviceDetailsRow = (Row) deviceDetailsIterator.next();
                if(deviceDetailsRow.get("TYPE") !=null)
                logSources.add((String) deviceDetailsRow.get("TYPE"));
            }
        }

        /** Security Application **/
        SelectQuery securityselectQuery = new SelectQueryImpl(Table.getTable(TableNameConstants.SYSLOG_ADDONS));
        securityselectQuery.addSelectColumn(Column.getColumn(TableNameConstants.SYSLOG_ADDONS, "*"));
        securityselectQuery.addSelectColumn(Column.getColumn(TableNameConstants.SECURITYDETAILS, "*"));
        securityselectQuery.addJoin(new Join(TableNameConstants.SYSLOG_ADDONS, TableNameConstants.SECURITYDETAILS, new String[]{"SECURITYID"}, new String[]{"SECURITYID"}, Join.INNER_JOIN));
        DataObject dataObject1 = DataAccess.get(securityselectQuery);
        if (!dataObject1.isEmpty()) {
            Iterator securityApplicationIterator = dataObject1.getRows(TableNameConstants.SECURITYDETAILS);
            while (securityApplicationIterator.hasNext()) {
                Row deviceDetailsRow = (Row) securityApplicationIterator.next();
                if(deviceDetailsRow.get("SECAPPTYPE") !=null)
                    secApplication.add((String) deviceDetailsRow.get("SECAPPTYPE"));
            }
        }

        /** Application **/

        SelectQuery sq = new SelectQueryImpl(Table.getTable(com.manageengine.itsf.common.database.constants.TableNameConstants.APPRESOURCES));
        sq.addSelectColumn(Column.getColumn(com.manageengine.itsf.common.database.constants.TableNameConstants.APPRESOURCES, "*"));
        sq.addSelectColumn(Column.getColumn(com.manageengine.itsf.common.database.constants.TableNameConstants.FORMAT_DETAILS, "*"));
        sq.addJoin(new Join(com.manageengine.itsf.common.database.constants.TableNameConstants.APPRESOURCES, com.manageengine.itsf.common.database.constants.TableNameConstants.FORMAT_DETAILS, new String[]{"FORMATID"}, new String[]{"FORMATID"}, Join.INNER_JOIN));
        DataObject dObj = PersistenceDBUtil.getPersistence().get(sq);
        Iterator<?> itr = dObj.getRows(com.manageengine.itsf.common.database.constants.TableNameConstants.FORMAT_DETAILS);
        while (itr.hasNext()) {
            Row formatDetailsRow = (Row) itr.next();
            if (formatDetailsRow.get("FORMATNAME") != null)
                appResources.add((String) formatDetailsRow.get("FORMATNAME"));
        }


    }

    public static void printPowershellcommand() throws Exception
    {
        /*** Services , HDD/SSD , SysEvtCol CPU ***/

        String command1 = "powershell.exe  Get-Service | Where-Object {$_.displayname -like 'ManageEngine*'}";
        //@{Name="GB";Expression={$_.size/1GB}}
        Process powerShellProcess1 = Runtime.getRuntime().exec(command1);

        powerShellProcess1.getOutputStream().close();
        String line1;
        //myWriter.write("Standard Output:");
        System.out.println("\nStandard Output:");
        System.out.println("\n Manage Engine Service List ");
        BufferedReader stdout1 = new BufferedReader(new InputStreamReader(
                powerShellProcess1.getInputStream()));
        outputWriter.write("\n Manage Engine Service List ");
        while ((line1 = stdout1.readLine()) != null)
        {
            outputWriter.write("\n"+line1);
            System.out.println(line1);
        }
        stdout1.close();
        BufferedReader stderr1 = new BufferedReader(new InputStreamReader(
                powerShellProcess1.getErrorStream()));
        while ((line1 = stderr1.readLine()) != null) {
            outputWriter.write("\n Error getting Manage Engine Service List "+line1);
            System.out.println("Error getting Manage Engine Service List"+line1);
        }
        stderr1.close();

        String command = "powershell.exe  Get-physicaldisk | Select FriendlyName, MediaType,@{Name='GB';Expression={$_.size/1GB}}";
        //@{Name="GB";Expression={$_.size/1GB}}
        Process powerShellProcess = Runtime.getRuntime().exec(command);

        powerShellProcess.getOutputStream().close();
        String line;
        outputWriter.write("\nStandard Output:");
        System.out.println("Standard Output:");

        BufferedReader stdout = new BufferedReader(new InputStreamReader(
                powerShellProcess.getInputStream()));
        outputWriter.write("\nDisk information : ");
        while ((line = stdout.readLine()) != null)
        {
            //myWriter.write("\n"+line);
            outputWriter.write("\n"+line);
            System.out.println(line);
        }
        stdout.close();

        BufferedReader stderr = new BufferedReader(new InputStreamReader(
                powerShellProcess.getErrorStream()));
        while ((line = stderr.readLine()) != null) {
            outputWriter.write("\nError getting disk information"+line);
            System.out.println("Error getting disk information"+line);
        }
        stderr.close();


        String command2 = "powershell.exe  (Get-Counter '\\Process(SysEvtCol)\\% Processor Time').CounterSamples | Select InstanceName,@{Name=\\\"CPU %\\\";Expression={[Decimal]::Round(($_.CookedValue / 12), 2)}}";
        //@{Name="GB";Expression={$_.size/1GB}}
        Process powerShellProcess2 = Runtime.getRuntime().exec(command2);

        powerShellProcess2.getOutputStream().close();
        String line2="";
        //myWriter.write("Standard Output:");
        System.out.println("Standard Output:");
        BufferedReader stdout2 = new BufferedReader(new InputStreamReader(
                powerShellProcess2.getInputStream()));
        outputWriter.write("\nSysEvtCol CPU ");
        while ((line2 = stdout2.readLine()) != null)
        {
            outputWriter.write("\n"+line2);
            System.out.println(line2);
        }
        stdout2.close();

        BufferedReader stderr2 = new BufferedReader(new InputStreamReader(
                powerShellProcess2.getErrorStream()));
        while ((line2 = stderr2.readLine()) != null) {
            outputWriter.write("\n Error getting SysEvtCol CPU"+line2);
            System.out.println("\n Error getting SysEvtCol CPU"+line2);
        }
        stderr2.close();

    }

    public static void getDetailsfromCustomer() throws Exception
    {
        System.out.println("Is it Virutal Machine \nIf yes, Enter 1 \nElse, Enter 2");
        Scanner sc= new Scanner(System.in); //System.in is a standard input stream.
        int VirtualMachine= sc.nextInt(); //reads string.
        if(VirtualMachine == 1) {
            Machine="Virtual";
            System.out.println("Does VM Resource(RAM & CPU) Reserved ? Enter (Yes or No or Currently Notsure)");
            VMReservation = sc.next(); //reads string.
            System.out.println("Does VM disk overprovisioning done ? Enter (Yes or No or Currently Notsure)");
            VMoverprovisioning = sc.next(); //reads string.
            System.out.println("VM Resource(RAM & CPU) : " + VMReservation);
            System.out.println("VM overprovisioning : " + VMoverprovisioning);
        }
        else{
            System.out.println("");
            Machine="Physical";
        }
    }
    public static void getScheduledstats() throws Exception
    {
        try {
            /*** Scheduled reports ***/
            scheduledReports = DBUtil.getCount(com.adventnet.la.util.TableNameConstants.TABLE_EXPORT_SCHEDULES, null);
            //System.out.println("scheduledReports : "+scheduledReports);

            /*** Scheduled compliance ***/
            scheduledCompilance = DBUtil.getCount("ExportScheduleConfigurations", new Criteria(Column.getColumn("ExportScheduleConfigurations", "TABLE_NAME"),"COMPLIANCE_SCHEDULE" , QueryConstants.EQUAL));
            //System.out.println("scheduledCompilance : "+scheduledCompilance);

            /*** Scheduled import ***/
            Criteria crt = new Criteria(Column.getColumn("ELAImportlogconfigurations", "SCHEDULE_ID"), -1, QueryConstants.NOT_EQUAL);
            scheduledImport = DBUtil.getCount("ELAImportlogconfigurations", crt);
        }
        catch (Exception e)
        {
            System.out.println("Exception during get getScheduledstats "+e);
        }
        //System.out.println("scheduledImport : "+scheduledImport);
    }
    public static void getCorrelationActivitystats() throws Exception
    {
        /*** Correlation rules ***/
    try
    {
        DataObject dobj = CorrelationUtil.getCompleteCorrelationRuleActionNotifData(null, SharedConstants.CORR_DEFAULT_RULE);
        corrRuleSize = dobj.size(TableNameConstants.CORRELATION_RULE_INFO);
        corractionsize = dobj.size(TableNameConstants.CORRELATION_ACTION_INFO);
        activeCorrRuleDetails = new ConcurrentHashMap<>();
        //System.out.println("corrRuleSize :"+corrRuleSize+" corractionsize :"+corractionsize);
        actionDetails = new ConcurrentHashMap<>();
        if(corrRuleSize <= 0)
        {
            System.out.println("No rules Configured");
            return;
        }
        List<Long> configuredRules = new ArrayList<>(corrRuleSize);
        Iterator<?> ruleItr = dobj.getRows(TableNameConstants.CORRELATION_RULE_INFO);
        while (ruleItr.hasNext())
        {
            try
            {
                Row ruleInfo = (Row) ruleItr.next();
                CorrelationStatus status = CorrelationStatus.getStatus((Long)ruleInfo.get("STATUS")); // No I18N
                Long ruleID = (Long) ruleInfo.get("RULE_ID");
                //System.out.println("ruleID : "+ruleID+"Status : "+status);
                if(status == CorrelationStatus.ENABLE)
                {
                    activeCorrRuleDetails.put(ruleID,ruleInfo.get("RULE_DISPLAY_NAME").toString());
                    Criteria ruleCriteria = new Criteria(Column.getColumn(TableNameConstants.CORRELATION_CONFIGURED_ACTIONS , "RULE_ID") , ruleID, QueryConstants.EQUAL);
                    Iterator<?> actionItr = dobj.getRows(CORRELATION_ACTION_INFO,ruleCriteria,new Join(TableNameConstants.CORRELATION_CONFIGURED_ACTIONS,TableNameConstants.CORRELATION_ACTION_INFO, new String[]{"ACTION_ID"}, new String[]{"ACTION_ID"}, Join.INNER_JOIN));
                    while(actionItr.hasNext())
                    {
                        Row actionInfo = (Row) actionItr.next();
                        actionDetails.put((Long) actionInfo.get("ACTION_ID"),actionInfo.get("DISPLAY_NAME").toString());
                    }
                }
            }
            catch (Exception exp)
            {
                System.out.println("Exception in getCorrelationActivitystats : "+exp);
            }


        /*** Session Activity ***/
        DataObject dataObject = ActivityUtil.getCompleteActivityData();
        Iterator<?> activityIterator = dataObject.getRows(TableNameConstants.ACTIVITY_PROFILE);
        activeSessionRuleDetails = new ConcurrentHashMap<>();
        sessionActivityRulesize = dataObject.size(TableNameConstants.ACTIVITY_RULE_PROVIDERS);
        while (activityIterator.hasNext())
        {
            Row activityProfile = (Row) activityIterator.next();
            Long profileID = (Long) activityProfile.get("PROFILE_ID");
            ActivityProfileInfo profileInfo = new ActivityProfileInfo(profileID);

            //Iterate through activity providers
            Criteria providerCriteria = new Criteria(Column.getColumn(TableNameConstants.ACTIVITY_RULE_PROVIDERS, "PROFILE_ID"), profileID, QueryConstants.EQUAL);
            Iterator providerIterator = dataObject.getRows(TableNameConstants.ACTIVITY_RULE_PROVIDERS, providerCriteria);
            while (providerIterator.hasNext())
            {
                Row ruleProvider = (Row) providerIterator.next();
                ActivityProviderInfo providerInfo = ActivityRuleInitializer.initActivityProvider(ruleProvider, dataObject);
                if (providerInfo != null)
                {
                    profileInfo.addProvider(providerInfo);
                    if(providerInfo.getStatus() == CorrelationStatus.ENABLE)
                    {
                        activeSessionRuleDetails.put(providerInfo.getRuleID(),ruleProvider.get("DISPLAY_NAME").toString());
                    }
                }
            }
        }
    }
}
    catch (Exception e)
    {
        System.out.println("Exception during CorrelationAcitivity "+e);
    }
 }

private static long getFolderSize(File folder)
    {
        long length = 0;

        // listFiles() is used to list the
        // contents of the given folder
        File[] files = folder.listFiles();

        int count = files.length;

        // loop for traversing the directory
        for (int i = 0; i < count; i++) {
            if (files[i].isFile()) {
                length += files[i].length();
            }
            else {
                length += getFolderSize(files[i]);
            }
        }
        return length;
    }

}

package burp;
/* Copyright (C) 2010 Paul Haas <phaas AT redspin DOT com> 
 * Licensed under the GNU Public License version 3.0 or greater
 *
 * Advanced Burp Suite Automation :
 * This tool accepts a URL, output_name, and an optional cookie string
 * It adds the URL's domain to Burp's scope then begins spidering from the
 * provided URL. Each request/reply is scanned passively for issues, and any
 * URLs with parameters are sent to Burp's active scanner. When testing is
 * finished, a session file is created with the results. The optional cookie
 * string is appended to all requests and is used to test applications requring
 * authentication.
 *
 * Output Files:
 *	output_name.zip - Burp's session file
 *	output_name.urls - List of URLs seen during testing
 *	output_name.issues - Full detail list of issues in tab delimited format
 *
 * See http://portswigger.net/misc/ for IBurpExtender API info and code
 */
import java.net.URL;
import java.util.*;
import java.util.regex.*;
import java.io.*;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IMenuItemHandler;
import burp.IScanIssue;
import burp.IScanQueueItem;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class BurpExtender implements IBurpExtender
{
	public IBurpExtenderCallbacks mcallBacks;
	public URL url;
	public File outsession;
	public BufferedWriter outissues;
	public BufferedWriter outurls;
	public String cookies;
	public Date last_request;
	public boolean scan_quit = false; // Quit after scanning: false = yes, true = prompt
	public boolean monitor_thread = false;
	public Vector<IScanQueueItem> scanqueue = new Vector<IScanQueueItem>();
	public File restore_state = new File("sodacan.zip"); // Configuration used for command-line scanning
	public int delay = 30; // Number of seconds to wait in loop for scanning and spidering to complete

	// Called to handle command line arguments passed to Burp

	/*=================================Modify======================*/
	private static String LOG_PATH;
    private static String LOG_NAME = "BurpLogFile_#.txt";
    private FileWriter fstream;
    private BufferedWriter out;
    public static final String DATE_FORMAT_NOW = "yyyyMMdd_HHmm";
    
    
    
    public BurpExtender() {
        System.out.println("BurpLogExtender Loaded");
        String mydir = System.getProperty ("user.dir");
        LOG_PATH = mydir.concat(File.separator).concat(LOG_NAME.replace("#",getTimeStamp()));
        System.out.println("LOG_PATH " + LOG_PATH);
        openFile();
    }
    
    private String getTimeStamp(){
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
        return sdf.format(cal.getTime());
    }
    
    
    private void openFile(){
        try {
            fstream = new FileWriter(LOG_PATH,true);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        out = new BufferedWriter(fstream);
    }
 
    
    //This function is called a single time as Burp Suite loads and needs to return
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {      	
    	mcallBacks = callbacks;  
    	mcallBacks.issueAlert("Attempting to restore state from '"+restore_state+"'");   
    	try	{mcallBacks.restoreState(restore_state);}
    	catch (Exception e)
    	{
    	    System.out.println("Unable to restore state from '"+restore_state+"': "+ e.getMessage()); 
            mcallBacks.exitSuite(false);  // Unconditional exit  
    	}
    	mcallBacks.issueAlert("Adding " + url.getHost() + " to scope, spider and scanner");    	
    	if (cookies != null) {mcallBacks.issueAlert("Including '" + cookies + "' to all in-scope requests. This will not appear in Burp's logs.");}
    	else {mcallBacks.issueAlert("No cookies provided, using cookies provided during spider");}
    	    	
    	try
    	{   		    		
    		URL url_scope = new URL(url.getProtocol(),url.getHost(),url.getPort(),"/");    
    		if (!mcallBacks.isInScope(url_scope))
			{mcallBacks.includeInScope(url_scope);}	
			last_request = new Date();
			mcallBacks.issueAlert("Starting spider on "+url+" at "+last_request);
			mcallBacks.sendToSpider(url);
			//mcallBacks.sendToRepeater(url,);
		}
		catch (Exception e)
        {
            System.out.println("Could not add URL to scope and spider, quitting: "+ e.getMessage()); 
            mcallBacks.exitSuite(false);  // Unconditional exit              
        }
    	return;
    }
    		
    // Called each time a HTTP request or HTTP reply is generated from a Burp tool
	public void processHttpMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	
    {    
		
		Date now = new Date();
	    SimpleDateFormat dateFormatter = new SimpleDateFormat("h:m:s a z");
	    String Response = null;
		try {
			Response = new String(messageInfo.getRequest());
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	    
	    writeFile(dateFormatter.format(now)+" "+"http://"+messageInfo.getHost()+":"+messageInfo.getPort()+" ["+messageInfo.getHost()+"]");
	    writeFile("======================================================");
		//writeFile(Response);
		writeFile(Response);
		writeFile("======================================================");
		
    	// Spider Reply: Add URL to passive and active scan
    	if (toolName == "spider")
    	{    		
			if (messageIsRequest)
			{
				// Update last request time and append cookies to request
				last_request = new Date();
				messageInfo = appendCookies(messageInfo);
			}
			// Scan and save URLS that are not 404 (Not Found)
			else
			{
				// Create a single instance of a monitor_thread
				if (!monitor_thread)
				{
					monitor_thread = true;
					monitorScan(messageInfo);				
				}
				// Send message to passive and active scanner
				else {spiderToScanner(messageInfo);}
				
				try 
				{
					// Write URL to file (Would be nice to include Request body after tab)
				   	if (messageInfo.getStatusCode() != 404)
				   	{
				   		outurls.write(messageInfo.getUrl().toString()+"\n");
				   		
				   	
				   	
				   	}
				}
				catch (Exception e)
		    	{System.out.println("Could not add URL to file: "+ e.getMessage());}	
		    		    
			}
    	}

		return;   
    }
	
	// Called whenever a scan issue occurs
	public void newScanIssue(IScanIssue issue)
	{	
		try
		{
			// Filter Information issue messages to STDOUT
			if (issue.getSeverity() != "Information")
			{System.out.println("scanner: "+issue.getSeverity()+" "+issue.getIssueName()+": "+issue.getUrl());}
			// Save session each time a High Finding is found
			else if (issue.getSeverity() == "High")
			{mcallBacks.saveState(outsession);}
		
			outissues.write(issue.getUrl() + "\t" +
				issue.getIssueName() + "\t" +			
				issue.getIssueBackground() + "\t" +
				issue.getIssueDetail() + "\t" +
				issue.getRemediationBackground() + "\t" +
				issue.getSeverity() +" ("+issue.getConfidence()+")\n" 
			);
		}
		catch (Exception e)
        {System.out.println("Error writing to issue file: "+ e.getMessage());}		
		return;
	}
	
    
    // Called when application is closed
    public void applicationClosing()
	{
		try 
		{
			outurls.close();
			outissues.close();
		}
		catch (Exception e)
        {System.out.println("Could not close files, quitting Burp Suite anyway: "+ e.getMessage());}
		return;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	// Called for a single thread to keep an eye on Burp's spider log, quit after 1 minute of no activity
	public int monitorScan(IHttpRequestResponse messageInfo)
	{
		try
		{
			Date currentTime = new Date();
			mcallBacks.issueAlert("Monitor thread started at "+currentTime+" and waiting for spider to complete");			
			// Continue waiting while last_request happened less than 1 minute ago
			while (last_request.getTime()+(delay * 100) > currentTime.getTime())
			{
					currentTime = new Date();
					Thread.currentThread().yield();
					Thread.currentThread().sleep(delay * 1000);
			}			
			mcallBacks.issueAlert("Spidering complete at "+last_request+", waiting for scanning completion");
			while (scanqueue.size() != 0) 
			{
				Iterator <IScanQueueItem> iterator = scanqueue.iterator();							
				while (iterator.hasNext()) {
					try { 
						IScanQueueItem isqi = iterator.next();								
						// Remove scan item from queue if it is finished
						if (isqi.getPercentageComplete() == 100){iterator.remove();}    							
						else if (isqi.getStatus() == "abandoned - too many errors" | isqi.getStatus() == "waiting to cancel"){iterator.remove();}
					}
					//See http://javabeanz.wordpress.com/2007/06/29/iterator-vs-enumeration/
					catch (ConcurrentModificationException e)
					{
						System.out.println("ConcurrentModificationException in monitorScan: " + e.getMessage());
						break;
					}									
				}
				currentTime = new Date();
				mcallBacks.issueAlert(scanqueue.size()+" remaining objects in scan queue at "+currentTime);	
				// Wait another 1 minute for completion
				Thread.currentThread().yield();
				Thread.currentThread().sleep(delay * 1000);	
			}	
			// Save results and quit
			currentTime = new Date();
			mcallBacks.issueAlert("Scanning complete at "+currentTime+". Saving session results to "+outsession);	
			mcallBacks.saveState(outsession);
			mcallBacks.exitSuite(scan_quit);
		}
		catch (Exception e)
        {
                System.out.println("Monitor thread encountered an unrecoverable error, saving files and quitting:"+ e.getMessage());
                // We might not be able to save our session, but try just in case
                try	{mcallBacks.saveState(outsession);}
				catch (Exception exception){exception.printStackTrace();}
				mcallBacks.exitSuite(scan_quit);
                return 1; 
        }	
		return 0;
	}
	
	// Called for each spider server reply to pass message on to passive/active scanning
	private void spiderToScanner(IHttpRequestResponse messageInfo)
	{
		try
        {          	
           	// Passively test everything
           	Boolean serviceIsHttps = messageInfo.getProtocol() == "https" ? true : false;
            mcallBacks.doPassiveScan(messageInfo.getHost(), messageInfo.getPort(), serviceIsHttps, messageInfo.getRequest(), messageInfo.getResponse());
        
        	// Only actively test items in scope
            if (mcallBacks.isInScope(messageInfo.getUrl()))
            {  
				boolean activescan = false;
				boolean inqueue = false;
		    	byte[] request = messageInfo.getRequest(); 
				String[][] parameters = mcallBacks.getParameters(request);
				for (int i = 0; i < parameters.length; i++)
		        {if (parameters[i][2] != "cookie"){activescan=true;break;}}		
		
				// Perform active testing only of URL has non cookie parameters	            
		        if (activescan)				
		        {    	
		        	// Add to active scan list and scan vector
		        	IScanQueueItem isqi = mcallBacks.doActiveScan(messageInfo.getHost(), messageInfo.getPort(), serviceIsHttps, messageInfo.getRequest());
					scanqueue.add(isqi); 		        	
				}
            }
        }
        catch (Exception e)
        {
            System.out.println("Error in spiderToScanner:" + e.getMessage()); 
        }	
	}		
	
	// Append/Modify HTTP cookies for all in-scope requests
	private IHttpRequestResponse appendCookies(IHttpRequestResponse messageInfo)
	{
		try
		{
			// If URL is in scope and we have cmdline specified cookies, append them to request
			if ((cookies != null) && mcallBacks.isInScope(messageInfo.getUrl()))
			{		
				byte[] request = messageInfo.getRequest();
				String request_string = new String(request);	
				Pattern pattern = Pattern.compile("^Cookie:\\s(.*?)$", Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
				Matcher matcher = pattern.matcher(request_string); 
				if (matcher.find())
				{request_string = matcher.replaceFirst(cookies);}
				else
				{
					pattern = Pattern.compile("\r\n\r\n");
					matcher = pattern.matcher(request_string); 
					request_string = matcher.replaceFirst("\r\n"+cookies+"\r\n\r\n");				
				}
				//System.out.println("Request: "+ request_string);
				request = request_string.getBytes();
				messageInfo.setRequest(request);
			}						
		}
		catch (Exception e)
        {System.out.println("Error setting Cookie Header: "+ e.getMessage());}
        return messageInfo;
	}

private void writeFile(String data){
        try {
            out.write(data);
            out.write("\r\n");
            out.flush();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
 
    private void writeFile(int numData){
        writeFile(Integer.toString(numData));
    }
 
    private void writeFile(int[] numAData){
        switch(numAData[0]){
            case ACTION_FOLLOW_RULES:
                writeFile("ACTION_FOLLOW_RULES");
                break;
            case ACTION_DO_INTERCEPT:
                writeFile("ACTION_DO_INTERCEPT");
                break;
            case ACTION_DONT_INTERCEPT:
                writeFile("ACTION_DONT_INTERCEPT");
                break;
            case ACTION_DROP:
                writeFile("ACTION_DROP");
                break;
        }
    }
 
    private void writeFile(boolean bData){
        writeFile(Boolean.toString(bData));
    }
 
    private void writeFile(byte[] btData){
        writeFile(new String(btData));
    }
 
    public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, String remoteHost, int remotePort, boolean serviceIsHttps, String httpMethod, String url, String resourceType, String statusCode, String responseContentType, byte[] message, int[] action) {
        
    	Date now = new Date();
    	SimpleDateFormat dateFormatter = new SimpleDateFormat("h:m:s a z");
    	if(messageIsRequest)
    	{
	    	writeFile("======================================================");
	    	writeFile(dateFormatter.format(now)+" "+"http://"+remoteHost+":"+remotePort+" ["+remoteHost+"]");
	    	writeFile("======================================================");
		writeFile(message);
		writeFile("======================================================");
    	}
        return message;
    }
	//==============================================================================
	public void setCommandLineArgs(String[] args)
	{
		if (!(args.length == 2 | args.length == 3))
		{
			System.out.println("Automated Burp Suite spidering and scanning tool\n");
			System.out.println("Usage: URL OUTNAME {COOKIE STRING}");
			System.out.println("\tURL = Start URL to start spidering from");
			System.out.println("\tOUTNAME = Filename w/o extension to save files");
			System.out.println("\tCookie = Optional cookie string to append to all HTTP requests");
			System.exit(1);
		}
		try {		
			// If URL doesn't start with a protocol, prepend one
			if (args[0].startsWith("http")){url = new URL(args[0]);}
			else {url = new URL("http://" + args[0]);}			
			if (url.getPort() == -1) // Java reverts to port=-1 if not explicitly specified
			{url = new URL(url.getProtocol(),url.getHost(),url.getDefaultPort(),url.getFile());}
			if (url.getFile() == "") // Java will assume a blank path if you do not supply one
			{url = new URL(url.getProtocol(),url.getHost(),url.getPort(),"/");}
			
			outsession = new File(args[1] + ".zip");
        	File aFile = new File(args[1] + ".issues");
        	outissues = new BufferedWriter(new FileWriter(aFile, aFile.exists()));
        	aFile = new File(args[1] + ".urls");
        	outurls = new BufferedWriter(new FileWriter(aFile, aFile.exists()));
        	
   			if (args.length == 3) // Set cookies if supplied
			{cookies = "Cookie: " + args[2];}			
		}
    	catch (java.net.MalformedURLException e) {
			System.out.println("Error converting string '" + args[0] + "' into URL: "+ e.getMessage()); 
			System.exit(2);
		}
		catch (IOException e)
        {
        	System.out.println("Error during IO: "+ e.getMessage()); 
            System.exit(3);
        }		
		catch (Exception e) {
			System.out.println("Other error occurred during commandline URL conversion: "+ e.getMessage()); 
			System.exit(4);		
		}			

		return;
	}
	       
			
}


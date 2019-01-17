package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;


public class BurpExtender implements IBurpExtender,IScannerCheck,ITab {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private JPopupMenu menu;  
	private AbstractTableModel model;
	private JTable table;
	private JScrollPane scrollPane;
	private List<Infor> infor = new ArrayList<Infor>();
	private final byte[][][] payloads = {{"\"<script>alert(/Xss_Check/)</script>".getBytes()},
			{"%22><img src=x onerror=alert(/Xss_Check/)><!--".getBytes()}};
	private final byte[][] keywords = {"/Xss_Check/".getBytes()}; 
	private final String signal = "permission";
	
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
        	//helpers�������������
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }
    
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.stdout = new PrintWriter(callbacks.getStdout(),true);//�õ������
		this.callbacks.setExtensionName("XSS_Scanner");//���ò������
		callbacks.registerScannerCheck(this);
		
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
            	//�Ҽ��˵�
            	menu = new JPopupMenu();
            	JMenuItem mClean;
            	mClean = new JMenuItem("���(C)");
            	menu.add(mClean);
            	
            	//menu.setVisible(true);
            	//�˵���Ӧ�¼�
            	mClean.addActionListener(new ActionListener() {
					
					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						stdout.println("clean");
						int last = infor.size();
						infor.clear();
						model.fireTableRowsUpdated(0, last);
					}
				});
            	
            	
            	//���
            	model = new TableModel();
            	table = new JTable(model);
            	table.addMouseListener(new MouseAdapter() {

					@Override
					public void mouseClicked(MouseEvent e) {
						// TODO Auto-generated method stub
						if(e.getButton() == MouseEvent.BUTTON3){
							menu.show(table,e.getX(),e.getY());//��ʾ�˵�
						}
					}
            		
				});
            	
            	scrollPane = new JScrollPane(table);
            	
            	//���Զ���������ʾΪBurp�ķ�����塢��ɫ������߼�ࣩ
            	callbacks.customizeUiComponent(mClean);
            	callbacks.customizeUiComponent(menu);
            	callbacks.customizeUiComponent(table);
            	callbacks.customizeUiComponent(scrollPane);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
                
            }
        });
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		// TODO Auto-generated method stub
		//byte[] req_match = baseRequestResponse.getResponse();
		//String s = new String(req_match);
		//if(!s.contains(signal)) {
			for(byte[][] payload:payloads){
				byte[] checkRequest = insertionPoint.buildRequest(payload[0]);//�������ݰ�
				byte[] keyword = keywords[0];
				//�õ�������Ϣ�����ͳ�ȥ��checkRequestResponse��Ӧ��Ϣ
				IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);
				String s = helpers.bytesToString(checkRequestResponse.getResponse());
				//��һ���ǲ��Ա���������������ڶ�������վlocaltion�ض�����ֵ�xss���
				if(!s.contains(signal) || s.contains(helpers.bytesToString(payload[0]))) {
					byte[] abc = helpers.stringToBytes(s);
					List<int[]> matches = getMatches(abc, keyword);//�õ���Ӧ��Ϣ
					if(matches.size()>0) {
						stdout.println("str:"+helpers.bytesToString(payload[0]));
						synchronized(infor){
							int row = infor.size();
							//��ƥ�����������Ϣʵ����
							infor.add(new Infor(helpers.bytesToString(payload[0]),helpers.analyzeRequest(checkRequestResponse).getUrl()));
							//���±����Ϣ
							model.fireTableRowsInserted(row, row);
							}
						}
					}
				}
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getTabCaption() {
		//��ǩ������
		return "XSS_Scanner";
	}

	@Override
	public Component getUiComponent() {
		//���ر�ǩ���Զ���Ŀؼ�
		return scrollPane;
	}
	
	// ���ģ����
	class TableModel extends AbstractTableModel{

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		@Override
		public int getRowCount() {
			//����
			return infor.size();
		}

		@Override
		public int getColumnCount() {
			//����
			return 2;
		}
		
	    @Override
	    public String getColumnName(int columnIndex)
	    {
	    	//����
	        switch (columnIndex)
	        {
				case 0:
					return "payload";
				case 1:
					return "url";
				default:
					return null;
	        }
	    }
		
	    @Override
	    public Class<?> getColumnClass(int columnIndex)
	    {
	        return String.class;
	    }
	    
		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			// ÿ�ж�Ӧ��Ϣʵ����������
			Infor inforEntry = infor.get(rowIndex);
			
			switch(columnIndex){
			case 0:
				return inforEntry.payload;
			case 1:
				return inforEntry.url.toString();
			default:
				return null;
			}
		}
	}
	
	// ��Ϣʵ����
	private static class Infor{
		final String payload;//��Ϣ����
		final URL url;//��Ϣ����ҳ���URL
		
		Infor(String payload, URL url)
        {
            this.payload = payload;
            this.url = url;
        }
	}	
}



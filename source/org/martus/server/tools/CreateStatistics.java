/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2001-2004, Beneficent
Technology, Inc. (Benetech).

Martus is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later
version with the additions and exceptions described in the
accompanying Martus license file entitled "license.txt".

It is distributed WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, including warranties of fitness of purpose or
merchantability.  See the accompanying Martus License and
GPL license for more details on the required license terms
for this software.

You should have received a copy of the GNU General Public
License along with this program; if not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.

*/
package org.martus.server.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.Vector;
import org.martus.common.ContactInfo;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.database.Database;
import org.martus.common.database.FileDatabase;
import org.martus.common.database.ServerFileDatabase;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.util.UnicodeReader;
import org.martus.util.UnicodeWriter;


public class CreateStatistics
{
	public static void main(String[] args)
	{
		try
		{
			boolean prompt = true;
			boolean deletePrevious = false;
			File dataDir = null;
			File destinationDir = null;
			File keyPairFile = null;

			for (int i = 0; i < args.length; i++)
			{
				if(args[i].startsWith("--no-prompt"))
					prompt = false;
			
				if(args[i].startsWith("--delete-previous"))
					deletePrevious = true;
			
				String value = args[i].substring(args[i].indexOf("=")+1);
				if(args[i].startsWith("--packet-directory="))
					dataDir = new File(value);
				
				if(args[i].startsWith("--keypair"))
					keyPairFile = new File(value);
				
				if(args[i].startsWith("--destination-directory"))
					destinationDir = new File(value);
			}
			
			if(destinationDir == null || dataDir == null || keyPairFile == null)
			{
				System.err.println("Incorrect arguments: CreateStatistics [--no-prompt] [--delete-previous] --packet-directory=<packetdir> --keypair-file=<keypair> --destination-directory=<destinationdir>\n");
				System.exit(2);
			}
			
			destinationDir.mkdirs();
			if(prompt)
			{
				System.out.print("Enter server passphrase:");
				System.out.flush();
			}
			
			BufferedReader reader = new BufferedReader(new UnicodeReader(System.in));
			//TODO password is a string
			String passphrase = reader.readLine();
			MartusCrypto security = MartusServerUtilities.loadCurrentMartusSecurity(keyPairFile, passphrase.toCharArray());

			new CreateStatistics(security, dataDir, destinationDir, deletePrevious);
		}
		catch(Exception e)
		{
			System.err.println("CreateStatistics.main: " + e);
			e.printStackTrace();
			System.exit(1);
		}
		System.out.println("Done!");
		System.exit(0);
	}
	
	public CreateStatistics(MartusCrypto securityToUse, File dataDirToUse, File destinationDirToUse, boolean deletePreviousToUse) throws Exception
	{
		security = securityToUse;
		deletePrevious = deletePreviousToUse;
		destinationDir = destinationDirToUse;
		fileDatabase = new ServerFileDatabase(dataDirToUse, security);
		fileDatabase.initialize();
		
		CreateAccountStatistics();
//		CreateBulletinStatistics();
//		CreatePacketStatistics();
//		CreateMagicWordStatistics();
	}
	
	private void CreateAccountStatistics() throws Exception
	{
		System.out.println("Creating Account Statistics");
		File accountStats = new File(destinationDir,ACCOUNT_STATS_FILE_NAME);
		if(deletePrevious)
			accountStats.delete();
		if(accountStats.exists())
			throw new Exception("File Exists.  Please delete before running: "+accountStats.getAbsolutePath());
		
		UnicodeWriter writer = new UnicodeWriter(accountStats);
		writer.writeln(ACCOUNT_STATISTICS_HEADER);
		fileDatabase.visitAllAccounts(new AccountVisitor(writer));
		writer.close();
	}

	class AccountVisitor implements Database.AccountVisitor 
	{
		public AccountVisitor(UnicodeWriter writerToUse)
		{
			writer = writerToUse;
		}
		
		public void visit(String accountId)
		{
			File accountDir = fileDatabase.getAbsoluteAccountDirectory(accountId);
			File bucket = accountDir.getParentFile();
			String publicCode = "";
			try
			{
				publicCode = MartusCrypto.computeFormattedPublicCode(accountId);
			}
			catch(Exception e)
			{
				publicCode = "ERROR: " + e;
			}
			
			try
			{
				String author = "";
				String organization = "";
				String email = "";
				String webpage = "";
				String phone = "";
				String address = "";
				try
				{
					File contactFile = fileDatabase.getContactInfoFile(accountId);
					Vector contactInfo = ContactInfo.loadFromFile(contactFile);
					int size = contactInfo.size();
					String contactAccountId;
					if(size>0)
					{
						contactAccountId = (String)contactInfo.get(0);
						if(!contactAccountId.equalsIgnoreCase(accountId))
						{
							author = "Error: AccountId doesn't match contactInfo's AccountId";
							throw new IOException();
						}			
					}
					
					if(size>2)
						author = (String)(contactInfo.get(2));
					if(size>3)
						organization = (String)(contactInfo.get(3));
					if(size>4)
						email = (String)(contactInfo.get(4));
					if(size>5)
						webpage = (String)(contactInfo.get(5));
					if(size>6)
						phone = (String)(contactInfo.get(6));
					if(size>7)
						address = (String)(contactInfo.get(7));
				}
				catch (IOException e)
				{
				}
				
				String accountInfo = 
					getNormalizedString(publicCode) + DELIMITER +
					getNormalizedString(author) + DELIMITER +
					getNormalizedString(organization) + DELIMITER +
					getNormalizedString(email) + DELIMITER +
					getNormalizedString(webpage) + DELIMITER +
					getNormalizedString(phone) + DELIMITER +
					getNormalizedString(address) + DELIMITER +
					getNormalizedString(bucket.getName() + "/" + accountDir.getName()) + DELIMITER + 
					getNormalizedString(accountId);

				writer.writeln(accountInfo);
			}
			catch(IOException e1)
			{
				e1.printStackTrace();
			}
		}
		private UnicodeWriter writer;
	}
	
/*	private void CreateBulletinStatistics()
	{
		System.out.println("Creating Bulletin Statistics");

	}

	private void CreatePacketStatistics()
	{
		System.out.println("Creating Packet Statistics");

	}

	private void CreateMagicWordStatistics()
	{
		System.out.println("Creating Magic Word Statistics");

	}
*/

	
	String getNormalizedString(Object rawdata)
	{
		String data = (String)rawdata;
		String normalized = data.replaceAll("\"", "'");
		normalized = normalized.replaceAll("\n", " | ");
		return "\"" + normalized + "\"";
	}
	
	private boolean deletePrevious;
	private MartusCrypto security;
	private File destinationDir;
	FileDatabase fileDatabase;
	
	final String DELIMITER = ",";
	final String ACCOUNT_STATS_FILE_NAME = "accounts.csv";
	final String ACCOUNT_PUBLIC_CODE = "public code";
	final String ACCOUNT_AUTHOR = "author name";
	final String ACCOUNT_ORGANIZATION = "organization";
	final String ACCOUNT_EMAIL = "email";
	final String ACCOUNT_WEBPAGE = "web page";
	final String ACCOUNT_PHONE = "phone";
	final String ACCOUNT_ADDRESS = "address";
	final String ACCOUNT_BUCKET = "account bucket";
	final String ACCOUNT_PUBLIC_KEY = "public key";

	final String ACCOUNT_STATISTICS_HEADER = 
		getNormalizedString(ACCOUNT_PUBLIC_CODE) + DELIMITER + 
		getNormalizedString(ACCOUNT_AUTHOR) + DELIMITER + 
		getNormalizedString(ACCOUNT_ORGANIZATION) + DELIMITER + 
		getNormalizedString(ACCOUNT_EMAIL) + DELIMITER + 
		getNormalizedString(ACCOUNT_WEBPAGE) + DELIMITER + 
		getNormalizedString(ACCOUNT_PHONE) + DELIMITER + 
		getNormalizedString(ACCOUNT_ADDRESS) + DELIMITER + 
		getNormalizedString(ACCOUNT_BUCKET) + DELIMITER + 
		getNormalizedString(ACCOUNT_PUBLIC_KEY);
}

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
import java.text.DateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Vector;

import org.martus.common.BulletinStore;
import org.martus.common.ContactInfo;
import org.martus.common.CustomFields;
import org.martus.common.FieldSpec;
import org.martus.common.HQKey;
import org.martus.common.HQKeys;
import org.martus.common.LoggerInterface;
import org.martus.common.MartusUtilities;
import org.martus.common.MartusXml;
import org.martus.common.StandardFieldSpecs;
import org.martus.common.bulletin.BulletinConstants;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.FileDatabase;
import org.martus.common.database.ServerFileDatabase;
import org.martus.common.database.FileDatabase.TooManyAccountsException;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.FieldDataPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.utilities.MartusFlexidate;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.server.foramplifiers.ServerForAmplifiers;
import org.martus.server.forclients.AuthorizeLog;
import org.martus.server.forclients.AuthorizeLogEntry;
import org.martus.server.forclients.ServerForClients;
import org.martus.server.main.MartusServer;
import org.martus.util.FileInputStreamWithSeek;
import org.martus.util.UnicodeReader;
import org.martus.util.UnicodeWriter;
import org.martus.util.Base64.InvalidBase64Exception;


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
			File adminStartupDir = null;

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

				if(args[i].startsWith("--admin-startup-directory"))
					adminStartupDir = new File(value);
			}
			
			if(destinationDir == null || dataDir == null || keyPairFile == null || adminStartupDir == null)
			{
				System.err.println("Incorrect arguments: CreateStatistics [--no-prompt] [--delete-previous] --packet-directory=<packetdir> --keypair-file=<keypair> --destination-directory=<destinationDir> --admin-startup-directory=<adminStartupConfigDir>\n");
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

			new CreateStatistics(security, dataDir, destinationDir, adminStartupDir, deletePrevious);
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
	public CreateStatistics(MartusCrypto securityToUse, File dataDirToUse, File destinationDirToUse, File adminStartupDirToUse, boolean deletePreviousToUse) throws Exception
	{
		security = securityToUse;
		deletePrevious = deletePreviousToUse;
		packetsDir = dataDirToUse;
		destinationDir = destinationDirToUse;
		adminStartupDir = adminStartupDirToUse;
		fileDatabase = new ServerFileDatabase(dataDirToUse, security);
		fileDatabase.initialize();
		clientsThatCanUpload = MartusUtilities.loadCanUploadFile(new File(packetsDir.getParentFile(), ServerForClients.UPLOADSOKFILENAME));
		bannedClients = MartusUtilities.loadBannedClients(new File(adminStartupDir, ServerForClients.BANNEDCLIENTSFILENAME));

		UnicodeReader reader = new UnicodeReader(new File(adminStartupDir, MartusServer.HIDDENPACKETSFILENAME));
		hiddenBulletinIds = MartusServerUtilities.getHiddenPacketsList(reader);
		
		clientsNotToAmplify = MartusUtilities.loadClientsNotAmplified(new File(adminStartupDir, ServerForAmplifiers.CLIENTS_NOT_TO_AMPLIFY_FILENAME));
		authorizeLog = new AuthorizeLog(security, new NullLogger(), new File(packetsDir.getParentFile(), ServerForClients.AUTHORIZELOGFILENAME));  		
		authorizeLog.loadFile();

		CreateAccountStatistics();
		CreateBulletinStatistics();
	}

	private void CreateAccountStatistics() throws Exception
	{
		final File accountStatsError = new File(destinationDir,ACCOUNT_STATS_FILE_NAME + ERR_EXT + CSV_EXT);
		class AccountVisitor implements Database.AccountVisitor 
		{
			public AccountVisitor(UnicodeWriter writerToUse)
			{
				writer = writerToUse;
			}
			
			public void visit(String accountId)
			{
				errorOccured = false;
				File accountDir = fileDatabase.getAbsoluteAccountDirectory(accountId);
				File bucket = accountDir.getParentFile();
				try
				{
					getPublicCode(accountId);
					getContactInfo(accountId);
					getAuthorizedInfo(publicCode);
					String uploadOk = isAllowedToUpload(accountId);
					String banned = isBanned(accountId);
					String notToAmplify = canAmplify(accountId);
					
					String accountInfo = 
						getNormalizedStringAndCheckForErrors(publicCode) + DELIMITER +
						getNormalizedStringAndCheckForErrors(uploadOk) + DELIMITER +
						getNormalizedStringAndCheckForErrors(banned) + DELIMITER +
						getNormalizedStringAndCheckForErrors(notToAmplify) + DELIMITER +
						getNormalizedStringAndCheckForErrors(clientAuthorizedDate) + DELIMITER +
						getNormalizedStringAndCheckForErrors(clientIPAddress) + DELIMITER +
						getNormalizedStringAndCheckForErrors(clientMagicWordGroup) + DELIMITER +
						getNormalizedStringAndCheckForErrors(author) + DELIMITER +
						getNormalizedStringAndCheckForErrors(organization) + DELIMITER +
						getNormalizedStringAndCheckForErrors(email) + DELIMITER +
						getNormalizedStringAndCheckForErrors(webpage) + DELIMITER +
						getNormalizedStringAndCheckForErrors(phone) + DELIMITER +
						getNormalizedStringAndCheckForErrors(address) + DELIMITER +
						getNormalizedStringAndCheckForErrors(bucket.getName() + "/" + accountDir.getName()) + DELIMITER + 
						getNormalizedStringAndCheckForErrors(accountId);

					writer.writeln(accountInfo);
					if(errorOccured)
						writeErrorLog(accountStatsError, ACCOUNT_STATISTICS_HEADER, accountInfo);
				}
				catch(Exception e1)
				{
					try
					{
						writeErrorLog(accountStatsError, ACCOUNT_STATISTICS_HEADER, e1.getMessage());
						e1.printStackTrace();
					}
					catch(IOException e2)
					{
						e2.printStackTrace();
					}
				}
			}
			
			private void getAuthorizedInfo(String publicCode)
			{
				AuthorizeLogEntry clientEntry = authorizeLog.getAuthorizedClientEntry(publicCode);
				clientAuthorizedDate = "";
				clientIPAddress = "";
				clientMagicWordGroup = "";
				if(clientEntry != null)
				{
					clientAuthorizedDate = clientEntry.getDate();
					clientIPAddress = clientEntry.getIp();
					clientMagicWordGroup = clientEntry.getGroupName();
				}
			}
			class NoContactInfo extends IOException{};
			class ContactInfoException extends IOException{};
			private void getContactInfo(String accountId)
			{
				author = ERROR_MSG;
				organization = ERROR_MSG;
				email = ERROR_MSG;
				webpage = ERROR_MSG;
				phone = ERROR_MSG;
				address = ERROR_MSG;
				
				try
				{
					File contactFile = fileDatabase.getContactInfoFile(accountId);
					if(!contactFile.exists())
						throw new NoContactInfo();
					Vector contactInfoRaw = ContactInfo.loadFromFile(contactFile);
					Vector contactInfo = ContactInfo.decodeContactInfoVectorIfNecessary(contactInfoRaw);
					int size = contactInfo.size();
					if(size>0)
					{
						String contactAccountIdInsideFile = (String)contactInfo.get(0);
						if(!security.verifySignatureOfVectorOfStrings(contactInfo, contactAccountIdInsideFile))
						{
							author = ERROR_MSG + " Signature failure contactInfo";
							throw new ContactInfoException();
						}
						
						if(!contactAccountIdInsideFile.equals(accountId))
						{
							author = ERROR_MSG + " AccountId doesn't match contactInfo's AccountId";
							throw new ContactInfoException();
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
				catch (NoContactInfo e)
				{
					author = "";
					organization = "";
					email = "";
					webpage = "";
					phone = "";
					address = "";
				}
				catch (ContactInfoException e)
				{
				}
				catch (IOException e)
				{
					author = ERROR_MSG + " IO exception contactInfo";
				}
				catch(InvalidBase64Exception e)
				{
					author = ERROR_MSG + " InvalidBase64Exception contactInfo";
				}
			}
			private String isAllowedToUpload(String accountId)
			{
				if(clientsThatCanUpload.contains(accountId))
					return ACCOUNT_UPLOAD_OK_TRUE;
				return	ACCOUNT_UPLOAD_OK_FALSE;
			}
			private String isBanned(String accountId)
			{
				if(bannedClients.contains(accountId))
					return ACCOUNT_BANNED_TRUE;
				return ACCOUNT_BANNED_FALSE;
			}
			private String canAmplify(String accountId)
			{
				if(clientsNotToAmplify.contains(accountId))
					return ACCOUNT_AMPLIFY_FALSE;
				return ACCOUNT_AMPLIFY_TRUE;
			}
	
			private UnicodeWriter writer;
			private String author;
			private String organization;
			private String email;
			private String webpage;
			private String phone;
			private String address;
			
			private String clientAuthorizedDate = "";
			private String clientIPAddress = "";
			private String clientMagicWordGroup = "";
		}

		
		System.out.println("Creating Account Statistics");
		File accountStats = new File(destinationDir,ACCOUNT_STATS_FILE_NAME + CSV_EXT);
		if(deletePrevious)
		{
			accountStats.delete();
			accountStatsError.delete();
		}
		
		if(accountStats.exists())
			throw new Exception("File Exists.  Please delete before running: "+accountStats.getAbsolutePath());
		if(accountStatsError.exists())
			throw new Exception("File Exists.  Please delete before running: "+accountStatsError.getAbsolutePath());
		
		UnicodeWriter writer = new UnicodeWriter(accountStats);
		try
		{
			writer.writeln(ACCOUNT_STATISTICS_HEADER);
			fileDatabase.visitAllAccounts(new AccountVisitor(writer));
		}
		finally
		{
			writer.close();
		}
	}

	private void CreateBulletinStatistics() throws Exception
	{
		final File bulletinStatsError = new File(destinationDir, BULLETIN_STATS_FILE_NAME + ERR_EXT + CSV_EXT);
		class BulletinVisitor implements Database.PacketVisitor
		{
			public BulletinVisitor(UnicodeWriter writerToUse)
			{
				writer = writerToUse;
			}
			public void visit(DatabaseKey key)
			{
				errorOccured = false;
				try
				{
					if(!BulletinHeaderPacket.isValidLocalId(key.getLocalId()))
						return;

					String martusVersionBulletionWasCreatedWith = getMartusBuildDateForBulletin(key);
					String bulletinType = getBulletinType(key);
					String isBulletinHidden = getIsBulletinHidden(key.getUniversalId());
					getPublicCode(key.getAccountId());
					getBulletinHeaderInfo(key);
					DatabaseKey burKey = MartusServerUtilities.getBurKey(key);
					String wasBurCreatedByThisServer = wasOriginalServer(burKey);
					String dateBulletinWasSavedOnServer = getOriginalUploadDate(burKey);
					getPacketInfo(key);
					
					String bulletinInfo =  getNormalizedStringAndCheckForErrors(key.getLocalId()) + DELIMITER +
					getNormalizedStringAndCheckForErrors(martusVersionBulletionWasCreatedWith) + DELIMITER + 
					getNormalizedStringAndCheckForErrors(bulletinType) + DELIMITER +
					getNormalizedStringAndCheckForErrors(Integer.toString(bulletinSizeInKBytes)) + DELIMITER + 
					getNormalizedStringAndCheckForErrors(allPrivate) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinHasCustomFields) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinCustomFieldTypes) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinTitle) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinSummary) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinLanguage) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinLocation) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinKeywords) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinDateCreated) + DELIMITER +
					getNormalizedStringAndCheckForErrors(bulletinDateEvent) + DELIMITER +
					getNormalizedStringAndCheckForErrors(Integer.toString(publicAttachmentCount)) + DELIMITER + 
					getNormalizedStringAndCheckForErrors(Integer.toString(privateAttachmentCount)) + DELIMITER + 
					getNormalizedStringAndCheckForErrors(wasBurCreatedByThisServer) + DELIMITER +
					getNormalizedStringAndCheckForErrors(isBulletinHidden) + DELIMITER +
					getNormalizedStringAndCheckForErrors(dateBulletinWasSavedOnServer) + DELIMITER +
					getNormalizedStringAndCheckForErrors(dateBulletinLastSaved) + DELIMITER +
					getNormalizedStringAndCheckForErrors(allHQsProxyUpload) + DELIMITER +
					getNormalizedStringAndCheckForErrors(hQsAuthorizedToRead) + DELIMITER +
					getNormalizedStringAndCheckForErrors(hQsAuthorizedToUpload) + DELIMITER +
					getNormalizedStringAndCheckForErrors(publicCode);
					
					writer.writeln(bulletinInfo);
					if(errorOccured)
						writeErrorLog(bulletinStatsError, BULLETIN_STATISTICS_HEADER, bulletinInfo);
				}
				catch(IOException e)
				{
					try
					{
						writeErrorLog(bulletinStatsError, BULLETIN_STATISTICS_HEADER, e.getMessage());
						e.printStackTrace();
					}
					catch(IOException e2)
					{
						e2.printStackTrace();
					}
				}
			}
			
			private void getPacketInfo(DatabaseKey key)
			{
				bulletinTitle = ERROR_MSG;
				bulletinSummary = ERROR_MSG;
				bulletinLanguage = ERROR_MSG;
				bulletinLocation = ERROR_MSG;
				bulletinKeywords = ERROR_MSG;
				bulletinDateCreated = ERROR_MSG;
				bulletinDateEvent = ERROR_MSG;
				bulletinHasCustomFields = ERROR_MSG;
				bulletinCustomFieldTypes = ERROR_MSG;
				
				try
				{
					BulletinHeaderPacket bhp = BulletinStore.loadBulletinHeaderPacket(fileDatabase, key, security);
					if(key.isDraft() || bhp.isAllPrivate())
					{
						bulletinTitle = "";
						bulletinSummary = "";
						bulletinLanguage = "";
						bulletinLocation = "";
						bulletinKeywords = "";
						bulletinDateCreated = "";
						bulletinDateEvent = "";
						bulletinHasCustomFields = "";
						bulletinCustomFieldTypes = "";
						return;
					}
					String fieldDataPacketId = bhp.getFieldDataPacketId();
					DatabaseKey fieldKey = DatabaseKey.createSealedKey(UniversalId.createFromAccountAndLocalId(
						bhp.getAccountId(), fieldDataPacketId));
					FieldSpec[] standardPublicFieldSpecs = StandardFieldSpecs.getDefaultPublicFieldSpecs();
					FieldDataPacket fdp = new FieldDataPacket(UniversalId.createFromAccountAndLocalId(
						bhp.getAccountId(), fieldDataPacketId), standardPublicFieldSpecs);
					FileInputStreamWithSeek in = new FileInputStreamWithSeek(fileDatabase.getFileForRecord(fieldKey));
					fdp.loadFromXml(in, bhp.getFieldDataSignature(), security);

					in.close();
					bulletinTitle = fdp.get(BulletinConstants.TAGTITLE);
					bulletinSummary = fdp.get(BulletinConstants.TAGSUMMARY);
					bulletinLanguage = fdp.get(BulletinConstants.TAGLANGUAGE);
					bulletinLocation = fdp.get(BulletinConstants.TAGLOCATION);
					bulletinKeywords = fdp.get(BulletinConstants.TAGKEYWORDS);
					bulletinDateCreated = fdp.get(BulletinConstants.TAGENTRYDATE);
					String eventDate = fdp.get(BulletinConstants.TAGEVENTDATE);
					MartusFlexidate mfd = MartusFlexidate.createFromMartusDateString(eventDate);
					String rawBeginDate = MartusFlexidate.toStoredDateFormat(mfd.getBeginDate());
					if(mfd.hasDateRange())
					{
						String rawEndDate = MartusFlexidate.toStoredDateFormat(mfd.getEndDate());
						bulletinDateEvent = rawBeginDate + " - " + rawEndDate;
					}
					else
					{
						bulletinDateEvent = rawBeginDate;
					}
					
					FieldSpec[] fieldSpecs = fdp.getFieldSpecs();
					CustomFields customFields = new CustomFields(fieldSpecs);
					if(FieldDataPacket.isNonCustomFieldSpecs(customFields))
						bulletinHasCustomFields = BULLETIN_HAS_CUSTOM_FIELDS_FALSE;
					else
						bulletinHasCustomFields = BULLETIN_HAS_CUSTOM_FIELDS_TRUE;
					
					bulletinCustomFieldTypes = "";
					for(int i = 0 ; i < fieldSpecs.length; ++i)
					{
						FieldSpec fieldSpec = fieldSpecs[i];
						if(!StandardFieldSpecs.isStandardFieldTag(fieldSpec.getTag()))
						{
							if(bulletinCustomFieldTypes.length()>0)
								bulletinCustomFieldTypes += ", ";
							bulletinCustomFieldTypes += FieldSpec.getTypeString(fieldSpec.getType()); 
						}
					}
				}
				catch(Exception e)
				{
					bulletinTitle = ERROR_MSG + " " + e.getMessage();
				}
			}

			private void getBulletinHeaderInfo(DatabaseKey key)
			{
				allPrivate = ERROR_MSG;
				dateBulletinLastSaved = ERROR_MSG;
				allHQsProxyUpload = ERROR_MSG;
				hQsAuthorizedToRead = ERROR_MSG;
				hQsAuthorizedToUpload = ERROR_MSG;
				publicAttachmentCount = -1;
				privateAttachmentCount = -1;
				bulletinSizeInKBytes = -1;

				try
				{
					BulletinHeaderPacket bhp = BulletinStore.loadBulletinHeaderPacket(fileDatabase, key, security);
					Calendar cal = new GregorianCalendar();
					cal.setTimeInMillis(bhp.getLastSavedTime());		
					dateBulletinLastSaved = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(cal.getTime());
					
					bulletinSizeInKBytes = MartusUtilities.getBulletinSize(fileDatabase, bhp) / 1000;
					String[] publicAttachments = bhp.getPublicAttachmentIds();
					String[] privateAttachments = bhp.getPrivateAttachmentIds();

					if(bhp.canAllHQsProxyUpload())
						allHQsProxyUpload = BULLETIN_ALL_HQS_PROXY_UPLOAD_TRUE;
					else
						allHQsProxyUpload = BULLETIN_ALL_HQS_PROXY_UPLOAD_FALSE;
					
					hQsAuthorizedToRead = getListOfHQKeys(bhp.getAuthorizedToReadKeys());
					hQsAuthorizedToUpload = getListOfHQKeys(bhp.getAuthorizedToUploadKeys());
					
					if(bhp.isAllPrivate())
					{
						allPrivate = BULLETIN_ALL_PRIVATE_TRUE;
						publicAttachmentCount = 0;
						privateAttachmentCount = publicAttachments.length;
						privateAttachmentCount += privateAttachments.length;
					}
					else
					{
						allPrivate = BULLETIN_ALL_PRIVATE_FALSE;
						publicAttachmentCount = publicAttachments.length;
						privateAttachmentCount = privateAttachments.length;
					}
				}
				catch(Exception e1)
				{
					allPrivate = ERROR_MSG + " " + e1;
				}
			}
			private String getIsBulletinHidden(UniversalId uId)
			{
				String bulletinHidden = ERROR_MSG;
				if(hiddenBulletinIds.contains(uId))
					bulletinHidden = BULLETIN_HIDDEN_TRUE;
				else
					bulletinHidden = BULLETIN_HIDDEN_FALSE;
				return bulletinHidden;
			}
			
			private String getListOfHQKeys(HQKeys keys)
			{
				String keyList = "";
				try
				{
					for(int i = 0; i < keys.size(); i++)
					{
						HQKey key = keys.get(i);
						if(keyList.length()>0)
							keyList += ", ";
						keyList += key.getPublicCode();
					}
				}
				catch(InvalidBase64Exception e)
				{
					keyList = ERROR_MSG;
				}
				return keyList;
			}
			private String getBulletinType(DatabaseKey key)
			{
				String bulletinType = ERROR_MSG + " not draft or sealed?";
				if(key.isSealed())
					bulletinType = BULLETIN_SEALED;
				else if(key.isDraft())
					bulletinType = BULLETIN_DRAFT;
				return bulletinType;
			}
			private String getMartusBuildDateForBulletin(DatabaseKey key) throws IOException, TooManyAccountsException
			{
				String martusBuildDateBulletionWasCreatedWith = ERROR_MSG;
				try
				{
					File bhpFile = fileDatabase.getFileForRecord(key);
					UnicodeReader reader = new UnicodeReader(bhpFile);
					String headerComment = reader.readLine();
					if(headerComment.startsWith(MartusXml.packetStartCommentStart))
					{
						String[] commentFields = headerComment.split(";");
						martusBuildDateBulletionWasCreatedWith =  commentFields[1];
					}
					else
						martusBuildDateBulletionWasCreatedWith = ERROR_MSG + " bhp didnot start with " + MartusXml.packetStartCommentStart;
				}
				catch(Exception e)
				{
					martusBuildDateBulletionWasCreatedWith = ERROR_MSG + " " + e.getMessage();
				}
				return martusBuildDateBulletionWasCreatedWith;
			}
			private String wasOriginalServer(DatabaseKey burKey)
			{
				String wasBurCreatedByThisServer = ERROR_MSG;
				try
				{
					if(!fileDatabase.getFileForRecord(burKey).exists())
					{
						wasBurCreatedByThisServer =ERROR_MSG + " missing BUR";
					}
					else
					{
						String burString = fileDatabase.readRecord(burKey, security);
						if(burString.length()==0)
							wasBurCreatedByThisServer = ERROR_MSG + " record empty?";
						else 
						{
							if(MartusServerUtilities.wasBurCreatedByThisCrypto(burString, security))
								wasBurCreatedByThisServer = BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER_TRUE;
							else
								wasBurCreatedByThisServer = BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER_FALSE;
						}
					}
				}
				catch(Exception e1)
				{
					wasBurCreatedByThisServer = ERROR_MSG + " " + e1;
				}
				return wasBurCreatedByThisServer;
			}
			private String getOriginalUploadDate(DatabaseKey burKey)
			{
				String uploadDate = ERROR_MSG;
				try
				{
					if(fileDatabase.getFileForRecord(burKey).exists())
					{
						String burString = fileDatabase.readRecord(burKey, security);
						if(burString.length()!=0)
						{
							String[] burData = burString.split("\n");
							uploadDate = burData[2];
						}
					}
				}
				catch(Exception e1)
				{
					uploadDate = ERROR_MSG + " " + e1;
				}
				return uploadDate;
			}
			
			UnicodeWriter writer;
			String allPrivate;
			String dateBulletinLastSaved;
			String allHQsProxyUpload;
			String hQsAuthorizedToRead;
			String hQsAuthorizedToUpload;
			String bulletinTitle;
			String bulletinSummary;
			String bulletinLanguage;
			String bulletinLocation;
			String bulletinKeywords;
			String bulletinHasCustomFields;
			String bulletinCustomFieldTypes;
			String bulletinDateCreated;
			String bulletinDateEvent;
			int publicAttachmentCount;
			int privateAttachmentCount;
			int bulletinSizeInKBytes;
		}
		
		System.out.println("Creating Bulletin Statistics");
		File bulletinStats = new File(destinationDir,BULLETIN_STATS_FILE_NAME + CSV_EXT);
		if(deletePrevious)
		{
			bulletinStats.delete();
			bulletinStatsError.delete();
		}
		if(bulletinStats.exists())
			throw new Exception("File Exists.  Please delete before running: "+bulletinStats.getAbsolutePath());
		if(bulletinStatsError.exists())
			throw new Exception("File Exists.  Please delete before running: "+bulletinStatsError.getAbsolutePath());
		
		UnicodeWriter writer = new UnicodeWriter(bulletinStats);
		try
		{
			writer.writeln(BULLETIN_STATISTICS_HEADER);
			fileDatabase.visitAllRecords(new BulletinVisitor(writer));
		}
		finally
		{
			writer.close();
		}
	}

	void getPublicCode(String accountId)
	{
		publicCode = "";
		try
		{
			publicCode = MartusCrypto.computeFormattedPublicCode(accountId);
		}
		catch(Exception e)
		{
			publicCode = ERROR_MSG + " " + e;
		}
	}
	public class NullLogger implements LoggerInterface
	{
		public NullLogger()	{}
		public void log(String message)	{}
	}
	void writeErrorLog(File bulletinStatsError, String headerString, String errorMsg) throws IOException
	{
		boolean includeErrorHeader = (!bulletinStatsError.exists());
		UnicodeWriter writerErr = new UnicodeWriter(bulletinStatsError, UnicodeWriter.APPEND);
		if(includeErrorHeader)
			writerErr.writeln(headerString);
		writerErr.writeln(errorMsg);
		writerErr.close();
	}
	String getNormalizedStringAndCheckForErrors(Object rawdata)
	{
		String data = (String)rawdata;
		if(data.startsWith(ERROR_MSG))
			errorOccured = true;
		String normalized = data.replaceAll("\"", "'");
		normalized = normalized.replaceAll("\n", " | ");
		return "\"" + normalized + "\"";
	}
	
	private boolean deletePrevious;
	private File packetsDir;
	private File adminStartupDir;
	MartusCrypto security;
	File destinationDir;
	String publicCode;
	boolean errorOccured;
	FileDatabase fileDatabase;
	Vector clientsThatCanUpload;
	Vector bannedClients;
	Vector clientsNotToAmplify;
	Vector hiddenBulletinIds;
	AuthorizeLog authorizeLog;
	
	final String DELIMITER = ",";
	final String ERROR_MSG = "Error:";
	final String ERR_EXT = ".err";
	final String CSV_EXT = ".csv";
	final String ACCOUNT_STATS_FILE_NAME = "accounts";
	final String ACCOUNT_PUBLIC_CODE = "public code";
	final String ACCOUNT_UPLOAD_OK = "can upload";
	final String ACCOUNT_BANNED = "banned";
	final String ACCOUNT_AMPLIFY = "can amplify";
	final String ACCOUNT_DATE_AUTHORIZED = "date authorized";
	final String ACCOUNT_IP = "ip address";
	final String ACCOUNT_GROUP = "group";
	final String ACCOUNT_AUTHOR = "author name";
	final String ACCOUNT_ORGANIZATION = "organization";
	final String ACCOUNT_EMAIL = "email";
	final String ACCOUNT_WEBPAGE = "web page";
	final String ACCOUNT_PHONE = "phone";
	final String ACCOUNT_ADDRESS = "address";
	final String ACCOUNT_FOLDER = "account folder";
	final String ACCOUNT_PUBLIC_KEY = "public key";
	final String ACCOUNT_UPLOAD_OK_TRUE = "1";
	final String ACCOUNT_UPLOAD_OK_FALSE = "0";
	final String ACCOUNT_BANNED_TRUE = "1";
	final String ACCOUNT_BANNED_FALSE = "0"; 
	final String ACCOUNT_AMPLIFY_TRUE = "1";
	final String ACCOUNT_AMPLIFY_FALSE = "0";

	final String ACCOUNT_STATISTICS_HEADER = 
		getNormalizedStringAndCheckForErrors(ACCOUNT_PUBLIC_CODE) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_UPLOAD_OK) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_BANNED) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_AMPLIFY) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_DATE_AUTHORIZED) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_IP) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_GROUP) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_AUTHOR) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_ORGANIZATION) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_EMAIL) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_WEBPAGE) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_PHONE) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_ADDRESS) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_FOLDER) + DELIMITER + 
		getNormalizedStringAndCheckForErrors(ACCOUNT_PUBLIC_KEY);

	final String BULLETIN_STATS_FILE_NAME = "bulletin";
	
	final String BULLETIN_HEADER_PACKET = "bulletin id";
	final String BULLETIN_MARTUS_VERSION = "martus build date";
	final String BULLETIN_TYPE = "type";
	final String BULLETIN_SIZE = "size (Kb)";
	final String BULLETIN_ALL_PRIVATE = "all private";
	final String BULLETIN_TITLE = "title";
	final String BULLETIN_SUMMARY = "summary";
	final String BULLETIN_LANGUAGE = "language";
	final String BULLETIN_LOCATION = "location";
	final String BULLETIN_KEYWORDS = "keywords";
	final String BULLETIN_DATE_CREATED = "date created";
	final String BULLETIN_DATE_EVENT = "event date";

	final String BULLETIN_PUBLIC_ATTACHMENT_COUNT = "public attachments";
	final String BULLETIN_PRIVATE_ATTACHMENT_COUNT = "private attachments";
	final String BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER = "original server";
	final String BULLETIN_DATE_UPLOADED = "date uploaded";
	final String BULLETIN_DATE_LAST_SAVED = "date last saved";
	final String BULLETIN_HAS_CUSTOM_FIELDS = "has custom fields";
	final String BULLETIN_CUSTOM_FIELD_TYPES = "custom field types";
	final String BULLETIN_HIDDEN = "hidden on server";
	final String BULLETIN_ALL_HQS_PROXY_UPLOAD = "all HQs proxy upload";
	final String BULLETIN_AUTHORIZED_TO_READ = "HQs authorized to read";
	final String BULLETIN_AUTHORIZED_TO_UPLOAD = "HQs authorized to upload";
	
	final String BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER_TRUE = "1";
	final String BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER_FALSE = "0";
	final String BULLETIN_DRAFT = "draft";
	final String BULLETIN_SEALED = "sealed";
	final String BULLETIN_ALL_PRIVATE_TRUE = "1";
	final String BULLETIN_ALL_PRIVATE_FALSE = "0";
	final String BULLETIN_ALL_HQS_PROXY_UPLOAD_TRUE = "1";
	final String BULLETIN_ALL_HQS_PROXY_UPLOAD_FALSE = "0";
	final String BULLETIN_HAS_CUSTOM_FIELDS_TRUE = "1";
	final String BULLETIN_HAS_CUSTOM_FIELDS_FALSE = "0";
	final String BULLETIN_HIDDEN_TRUE = "1"; 
	final String BULLETIN_HIDDEN_FALSE = "0"; 
	
	final String BULLETIN_STATISTICS_HEADER = 
		getNormalizedStringAndCheckForErrors(BULLETIN_HEADER_PACKET) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_MARTUS_VERSION) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_TYPE) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_SIZE) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_ALL_PRIVATE) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_HAS_CUSTOM_FIELDS) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_CUSTOM_FIELD_TYPES) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_TITLE) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_SUMMARY) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_LANGUAGE) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_LOCATION) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_KEYWORDS) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_DATE_CREATED) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_DATE_EVENT) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_PUBLIC_ATTACHMENT_COUNT) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_PRIVATE_ATTACHMENT_COUNT) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_ORIGINALLY_UPLOADED_TO_THIS_SERVER) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_HIDDEN) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_DATE_UPLOADED) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_DATE_LAST_SAVED) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_ALL_HQS_PROXY_UPLOAD) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_AUTHORIZED_TO_READ) + DELIMITER +
		getNormalizedStringAndCheckForErrors(BULLETIN_AUTHORIZED_TO_UPLOAD) + DELIMITER +
		getNormalizedStringAndCheckForErrors(ACCOUNT_PUBLIC_CODE);

}

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
package org.martus.server.forclients;

import java.util.GregorianCalendar;


public class AuthorizeLogEntry
{
	public AuthorizeLogEntry(String line)
	{
		super();
		date = getDateFromLineEntry(line);
		publicCode = getPublicCodeFromLineEntry(line);
		groupName = getGroupNameFromLineEntry(line);
	}
	
	public AuthorizeLogEntry(String publicCodeToUse, String groupNameToUse)
	{
		GregorianCalendar today = new GregorianCalendar();
		String year = new Integer(today.get(GregorianCalendar.YEAR)).toString();
		String month = new Integer(today.get(GregorianCalendar.MONTH)).toString();
		String day = new Integer(today.get(GregorianCalendar.DAY_OF_MONTH)).toString();
		
		date = year + "-" + month + "-" + day;
		
		publicCode = publicCodeToUse;
		groupName = groupNameToUse;
	}
	
	public String getDate()
	{
		return date;
	}

	public String getGroupName()
	{
		return groupName;
	}

	public String getPublicCode()
	{
		return publicCode;
	}
	
	static public String getDateFromLineEntry(String lineEntry)
	{
		int index = lineEntry.indexOf(FIELD_DELIMITER);
		return lineEntry.substring(0,index);
	}

	static public String getPublicCodeFromLineEntry(String lineEntry)
	{
		int startIndex = lineEntry.indexOf(FIELD_DELIMITER);
		int endIndex = lineEntry.lastIndexOf(FIELD_DELIMITER);
		return lineEntry.substring(startIndex+1,endIndex);
	}
	
	static public String getGroupNameFromLineEntry(String lineEntry)
	{
		int endIndex = lineEntry.lastIndexOf(FIELD_DELIMITER);
		return lineEntry.substring(endIndex+1);
	}
	
	public String toString()
	{
		return date + FIELD_DELIMITER + publicCode + FIELD_DELIMITER + groupName;
	}
	
	public static final String FIELD_DELIMITER = "\t";
	
	private String date;
	private String publicCode;
	private String groupName;

}

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

import org.martus.common.test.TestCaseEnhanced;


public class TestAuthorizeLogEntry extends TestCaseEnhanced
{
	public TestAuthorizeLogEntry(String name)
	{
		super(name);
	}
	
	public void testBasics()
	{
		String date = "01-02-2004";
		String code = "1234.1234.1234.1234";
		String group = "My group";
		
		String newClientLineEntry = date + AuthorizeLogEntry.FIELD_DELIMITER + code + AuthorizeLogEntry.FIELD_DELIMITER + group ;
		AuthorizeLogEntry entry = new AuthorizeLogEntry(newClientLineEntry);
		assertEquals("date not found?", date, entry.getDate());
		assertEquals("code not found?", code, entry.getPublicCode());
		assertEquals("group not found?", group, entry.getGroupName());
		
		assertEquals("to String didn't return same value?", newClientLineEntry, entry.toString());

		AuthorizeLogEntry entry2 = new AuthorizeLogEntry(code, group);

		GregorianCalendar today = new GregorianCalendar();
		String year = new Integer(today.get(GregorianCalendar.YEAR)).toString();
		String month = new Integer(today.get(GregorianCalendar.MONTH)).toString();
		String day = new Integer(today.get(GregorianCalendar.DAY_OF_MONTH)).toString();
		
		date = year + "-" + month + "-" + day;
		assertEquals("date not found?", date, entry2.getDate());
		assertEquals("code not found?", code, entry2.getPublicCode());
		assertEquals("group not found?", group, entry2.getGroupName());
		
	}
}

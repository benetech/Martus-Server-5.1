/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002-20014, Beneficent
Technology, Inc. (The Benetech Initiative).

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

package org.martus.server.formirroring;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.martus.common.crypto.MartusCrypto;
import org.martus.util.UnicodeReader;

public class TemplateInfoForMirroring 
{
	public TemplateInfoForMirroring(File file) throws Exception
	{
		name = file.getName();
		digest = computeDigest(file);
		Path path = file.toPath();
		lastModifiedMillis = Files.getLastModifiedTime(path).toMillis();
	}
	
	public TemplateInfoForMirroring(String infoAsString)
	{
		String[] pieces = infoAsString.split("\\t");
		name = pieces[0];
		digest = pieces[1];
		lastModifiedMillis = Long.parseLong(pieces[2]);
	}

	public String asString() 
	{
		return name + TAB + digest + TAB + lastModifiedMillis;
	}
	
	public String getName()
	{
		return name;
	}
	
	public long getLastModifiedMillis()
	{
		return lastModifiedMillis;
	}
	
	private String computeDigest(File file) throws Exception
	{
		UnicodeReader reader = new UnicodeReader(file);
		try
		{
			String contents = reader.readAll();
			return MartusCrypto.createDigestString(contents);
		}
		finally
		{
			reader.close();
		}
	}
	
	@Override
	public String toString() 
	{
		return asString();
	}
	
	@Override
	public int hashCode() 
	{
		return asString().hashCode();
	}
	
	@Override
	public boolean equals(Object rawOther) 
	{
		if(rawOther == this)
			return true;
		if(rawOther == null)
			return false;
		if(! (rawOther instanceof TemplateInfoForMirroring) )
			return false;
		
		TemplateInfoForMirroring other = (TemplateInfoForMirroring) rawOther;
		return asString().equals(other.asString());
	}
	
	private final static char TAB = '\t'; 
	
	private String name;
	private String digest;
	private long lastModifiedMillis;
}

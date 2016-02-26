package ch.fuchsnet.confluence;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.ConfluenceUser;

import java.security.Principal;


/*
Remote User Single Sign On Authenticator russo-confluence: 
Authenticating to Confluence with the X_Forwarded_User HTTP header
Copyright (C) 2014  Christian Loosli

This software may be modified and distributed under the terms
of the MIT license.  See the COPYING file for details.
 */

/**
 * Extension of DefaultAuthenticator that uses the Apache set X-Forwarded-User
 * header in a HTTPRequest object for single sign on. 
 * @author Christian Loosli
 *
 */
public class RussoConfluenceAuthenticator extends ConfluenceAuthenticator
{

	// Header we read. Has to be lowercase even if the header is set uppercase in apache
	private static final String strHeaderName = "x-forwarded-user";
	private static final long serialVersionUID = 1807345345435345234L;
	

	/**
	 * Default method getting the user, first calls the Confluence based method, then checks 
	 * for X-Forwarded-User in the header. This should ensure that everything using
	 * other methods than Apache Kerberos Auth should still work, but in addition to that, 
	 * the header set after Kerberos auth will be considered and should also allow a log-in. 
	 * 
	 * @param request The request containing the headers
	 * @param response The response sent
	 * @return The user principal, can be null if authentication failed. 
	 */
	public Principal getUser(HttpServletRequest request, HttpServletResponse response)
	{

		Principal user = null; 
		ConfluenceUser confluenceuser = null; 
		
		try
		{
			// This shall also take care of the user already being logged in, as the parent checks that. 
			user = super.getUser(request, response);
			String username = request.getHeader(strHeaderName);
			                                   		
			// Neither an already existing user nor a forwarded one in the header. 
			// This will return null, which should have Confluence redirect the user to the configurated login page
			if ( (user == null) && (username == null))
	        {

	            return user;
	        }
			

			
			if (user != null)
	        {
	            if ( (username != null) && (user.getName().equals(username)))
	            {
	                return user;
	            }
	            else
	            {
	            	return user; 
	            }
	        }
			
			try
			{
				confluenceuser = super.getUser(username);
				
				if(confluenceuser != null)
				{
					user = (Principal) confluenceuser; 
				}
			}
			catch (Exception e)
			{
				
			}
			        
	        return user;
		} 
		catch (Exception e) // catch class cast exceptions
		{
			return user; 
		}
	}

	@Override
	protected boolean authenticate(Principal pPrincipal, String pStrPwd) 
			throws AuthenticatorException
	{
		return super.authenticate(pPrincipal, pStrPwd);
	}

	@Override
	protected ConfluenceUser getUser(String pStrUsername)
	{
		return super.getUser(pStrUsername);
	}

}

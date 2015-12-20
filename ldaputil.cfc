<!---
  $RCSfile: ldaputil.cfc,v $
  $Author: acrum $

  Summary: This component handles all LDAP calls (authentication and inserts to the customer directories)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--->

<cfcomponent name="ldaputil" extends="com.global.base" displayname="LDAP Util" hint="Amkor standard ldap object used for user authetication and ldap look ups">
	<!--- set the default properties in case the user does not call the init method --->
	<cfscript>
		variables.ldapServerP = "";
		variables.ldapServerS = "";
		variables.ldapServerT = "";

		variables.ldapProps = structNew();
		variables.ldapProps.scope = 'subtree';
		variables.ldapProps.start = 'o=AAWW';
		variables.ldapProps.filter = '*';
		variables.ldapProps.attributes = 'uid,givenname,middleinitial,sn,title,department,companyname,c,cn,location,officeStreetAddress,officeCity,st,officeZIP,telephonenumber,facsimileTelephoneNumber,mail,mobile,manager,dominoUNID,o,ou,objectclass,dn,ShortName,PHYSICALDELIVERYOFFICENAME';
		variables.ldapProps.server = variables.ldapServerP;
		variables.ldapProps.userUID = '';
		variables.ldapProps.userPw = '';
	</cfscript>

	<cffunction name="init" displayname="init(string ldapServer, string ldapAttributes) as userDAO" hint="initilize the object" access="public" output="false" returntype="ldaputil">
		<cfargument name="ldapServerPrimary" displayname="string ldapServerPrimary" hint="the Primary LDAP server" type="string" required="no" default="#variables.ldapServerP#" />
		<cfargument name="ldapServerSecondary" displayname="string ldapServerSecondary" hint="the secondary LDAP server" type="string" required="no" default="#variables.ldapServerS#" />
		<cfargument name="ldapServerThird" displayname="string ldapServerPrimary" hint="the final fail over LDAP server" type="string" required="no" default="#variables.ldapServerT#" />
		<cfargument name="ldapAttributes" displayname="string ldapAttributes" hint="the default attributes" type="string" required="no" default="#variables.ldapProps.attributes#" />
		<cfargument name="ldapScope" displayname="string ldapScope" hint="the default scope to use" type="string" required="no" default="#variables.ldapProps.scope#" />
		<cfargument name="ldapStart" displayname="string ldapStart" hint="the default start to use" type="string" required="no" default="#variables.ldapProps.start#" />
		<cfargument name="ldapFilter" displayname="string ldapFilter" hint="the filter to use" type="string" required="no" default="#variables.ldapProps.filter#" />
		<cfargument name="ldapUserUID" displayname="string ldapUserUID" hint="the default authetication user id to use" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapUserPw" displayname="string ldapUserPw" hint="the defalut authentication user password to use" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<!--- overwrite the default settings with the values supplied from the user --->
		<cfscript>
			variables.ldapServerP = arguments.ldapServerPrimary;
			variables.ldapServerS = arguments.ldapServerSecondary;
			variables.ldapServerT = arguments.ldapServerThird;
			variables.ldapProps.scope = arguments.ldapScope;
			variables.ldapProps.start = arguments.ldapStart;
			variables.ldapProps.filter= arguments.ldapFilter;
			variables.ldapProps.attributes = arguments.ldapAttributes;
			variables.ldapProps.server = arguments.ldapServerPrimary;
			variables.ldapProps.userUID = arguments.ldapUserUID;
			variables.ldapProps.userPw = arguments.ldapUserPw;
		</cfscript>
		<cfreturn this />
	</cffunction>

	<cffunction name="isValidUsername" displayname="boolean isValidUsername(string userName)" hint="ensure that a user name does not contain invalide caracters" output="false" access="public" returntype="boolean">
		<cfargument name="userName" displayname="string userName" hint="the username to check"  type="string" required="yes" />
		<cfreturn (not(REFind("[^A-Za-z0-9]", arguments.userName) gt 0) and '' NEQ arguments.userName) />
	</cffunction>

	<!--- exposed authentication method --->
	<cffunction name="authenticate" displayname="authenticate(uid, password)" hint="autheticate user against a ldap server with triple server failover" access="public" returntype="query">
		<cfargument name="uid" displayname="uid" hint="standard amkor notes user id" type="string"  required="true" />
		<cfargument name="userPassword" displayname="user Password" hint="users standard amkor notes internet password" type="string"  required="true" />
		<cfscript>
			var loginerror = 0;
			var qValidate = '';
			var catchObj = structNew();
			var lProps = structCopy(variables.ldapProps);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			//set the local props to the arument values
			lProps.filter = '(uid=#arguments.uid#)';
			lProps.userUID = arguments.uid;
			lProps.userPw = arguments.userPassword;
		</cfscript>
		<!--- ensure that proper credentials are passed cause notes ldap is kinda funky and will return sucessful authentication when not really true --->
		<cfif not(isValidUsername(arguments.uid)) or arguments.userPassword is "">
			<cfthrow type="ldapUtil" detail="The user name or password are of an incorect type" extendedinfo="The user name and password can not be empty.  The user name can not contain @ or ." errorcode="ldapUtil1000" message="Invalid user credentials for authentication" />
		<cfelse>
			<cfset loginerror = 0 />
			<!--- attempt to authenticate via the primary ldap server --->
			<cftry>
				<cfset qValidate = this.queryLdap(lProps) />
				<cfcatch type="any" >
					<cfset catchObj.server1 = cfcatch />
					<cfset loginerror = 1 />
				</cfcatch>
			</cftry>
			<!--- Try the secondary ldap server if the primary fails --->
			<cfif loginerror EQ 1>
				<!--- reset the error message for the second server attempt --->
				<cfset loginerror = 0 />
				<cfset lProps.server = variables.ldapServerS />
				<cftry>
					<cfset qValidate = this.queryLdap(lProps) />
					<cfcatch type="any">
						<cfset catchObj.server2 = cfcatch />
						<cfset loginerror = 1 />
					</cfcatch>
				</cftry>
			</cfif>
			<!--- Try the third ldap server if both primary and secondary fail --->
			<cfif loginerror EQ 1>
				<cfset loginerror = 0 />
				<cfset lProps.server = variables.ldapServerT />
				<cftry>
					<cfset qValidate = this.queryLdap(lProps) />
					<cfcatch type="any">
						<cfset catchObj.server3 = cfcatch />
						<cfset loginerror = 1 />
					</cfcatch>
				</cftry>
			</cfif>
		</cfif>
		<cfif loginerror is 1 >
			<cfif Find("Inappropriate authentication", catchObj.server1.message) NEQ "0" or Find("Inappropriate authentication", catchObj.server2.message) NEQ "0" or Find("Inappropriate authentication", catchObj.server3.message) NEQ "0">
				<cfthrow type="ldapUtil" message="Invalid Credentials" detail="Could not autheticate with the supplied credentials." errorcode="ldapUtil1002" />
			<cfelse>
				<cfthrow type="ldapUtil"
						 message="Authenication request was refused by all three authenication servers"
						 detail="Request for authetication has been refused by all three LDAP servers.<br>
						 	     Primary LDAP Server :: #variables.ldapServerP#<br/>
								 Catch Details:<br/>
								 Type :: #catchObj.server1.type#<br/>
								 Message :: #catchObj.server1.message#<br/>
								 Detail ::#catchObj.server1.detail#<br/>
								 ExtendedInfo :: #catchObj.server1.ExtendedInfo#<br/>
								 Secondary LDAP Server :: #variables.ldapServerS#<br/>
								 Catch Details:<br/>
								 Type :: #catchObj.server2.type#<br/>
								 Message :: #catchObj.server2.message#<br/>
								 Detail ::#catchObj.server2.detail#<br/>
								 ExtendedInfo :: #catchObj.server2.ExtendedInfo#<br/>
								 Final LDAP Server :: #variables.ldapServerT#<br/>
								 Catch Details:<br/>
								 Type :: #catchObj.server3.type#<br/>
								 Message :: #catchObj.server3.message#<br/>
								 Detail ::#catchObj.server3.detail#<br/>
								 ExtendedInfo :: #catchObj.server3.ExtendedInfo#<br/>
								 " errorcode="ldapUtil1001"/>
			</cfif>
		</cfif>
		<cfreturn qValidate />
	</cffunction>

	<cffunction name="getGroup" returntype="query" access="public" output="false" displayname="Get All Groups" hint="I get a query off all groups in the directory" >
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.server = variables.ldapServerP;
			//set the local props to the arument values
			//lProps.filter = "(objectClass=dominoGroup)";
			lProps.filter = "(CN=Altiris*)";
			lProps.start = "";
			lProps.attributes = "*";
			lProps.userUID = arguments.ldapAuthId;
			lProps.userPw = arguments.ldapAuthPw;
		</cfscript>
		<cftry>
			<cfset qValidate = this.queryLdap(lProps) />
			<cfcatch type="any">
				<cfthrow type="ldapUtil"
					 message="LDAP query failed"
					 detail="Primary LDAP Server :: #variables.ldapServerP#<br/>
							 Catch Details:<br/>
							 Type :: #cfcatch.type#<br/>
							 Message :: #cfcatch.message#<br/>
							 Detail ::#cfcatch.detail#<br/>
							 ExtendedInfo :: #cfcatch.ExtendedInfo#<br/>
							 " errorcode="ldapUtil1003"/>
			</cfcatch>
		</cftry>
		<cfreturn qValidate>
	</cffunction>

	<cffunction name="findUserBy" displayname="findByUid(searchFor, searchBy, [ldapAuthId], [ldapAuthPw]) as boolean" hint="search LDAP for a user by user id" output="true" access="public" returntype="query">
		<cfargument name="searchFor" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="searchBy" displayname="string searchBy" hint="ldap filter to apply" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			var propDump = structNew();
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.server = variables.ldapServerP;
			//set the local props to the arument values
			lProps.filter = "(#arguments.searchBy#=#arguments.searchFor#)";
			lProps.userUID = arguments.ldapAuthId;
			lProps.userPw = arguments.ldapAuthPw;
			logit("info", lProps.filter, "Search for user", findUserBy, arguments);
		</cfscript>
		<cftry>
			<cfset qValidate = this.queryLdap(lProps) />
			<cfcatch type="any">
				<cfsavecontent variable="propDump">
					<cfdump var="#lProps#" />
				</cfsavecontent>
				<cfthrow type="ldapUtil"
					 message="LDAP query failed"
					 detail="Primary LDAP Server :: #variables.ldapServerP#<br/>
					 		 LDAP query Properties :: #propDump#<br/>
							 Catch Details:<br/>
							 Type :: #cfcatch.type#<br/>
							 Message :: #cfcatch.message#<br/>
							 Detail ::#cfcatch.detail#<br/>
							 ExtendedInfo :: #cfcatch.ExtendedInfo#<br/>
							 " errorcode="ldapUtil1003"/>
			</cfcatch>
		</cftry>
		<cfreturn qValidate>
	</cffunction>

	<cffunction name="query" displayname="findByUid(searchFor, searchBy, [ldapAuthId], [ldapAuthPw]) as boolean" hint="search LDAP for a user by user id" output="true" access="public" returntype="query">
		<cfargument name="queryParam" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			var propDump = structNew();
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.server = variables.ldapServerP;
			//set the local props to the arument values
			lProps.filter = "#arguments.queryParam#";
			lProps.userUID = arguments.ldapAuthId;
			lProps.userPw = arguments.ldapAuthPw;
			logit("info", lProps.filter, "Query By", #arguments.queryParam#, arguments);
		</cfscript>
		<cftry>
			<cfset qValidate = this.queryLdap(lProps) />
			<cfcatch type="any">
				<cfsavecontent variable="propDump">
					<cfdump var="#lProps#" />
				</cfsavecontent>
				<cfthrow type="ldapUtil"
					 message="LDAP query failed"
					 detail="Primary LDAP Server :: #variables.ldapServerP#<br/>
					 		 LDAP query Properties :: #propDump#<br/>
							 Catch Details:<br/>
							 Type :: #cfcatch.type#<br/>
							 Message :: #cfcatch.message#<br/>
							 Detail ::#cfcatch.detail#<br/>
							 ExtendedInfo :: #cfcatch.ExtendedInfo#<br/>
							 " errorcode="ldapUtil1003"/>
			</cfcatch>
		</cftry>
		<cfreturn qValidate>
	</cffunction>

	<cffunction name="findGroupBy" returntype="query" access="public" output="false" displayname="Get User Groups" hint="I return a query of all the groups a user belongs to" >
		<cfargument name="searchFor" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="searchBy" displayname="string searchBy" hint="ldap filter to apply" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.userPw = arguments.ldapAuthPw;
			lProps.server = variables.ldapServerP;
			//set local prop filter
			lProps.filter = "(&(#arguments.searchBy#=#arguments.searchFor#)(objectClass=dominoGroup)))";
			//ldap attributes to get when searching
			lProps.attributes = "member, cn";
			lProps.start = "";
		</cfscript>
		<cfset qValidate = this.queryLdap(lProps) />
		<cfreturn qValidate>
	</cffunction>



	<cffunction name="getUsersGroups" returntype="query" access="public" output="false" displayname="Get User Groups" hint="I return a query of all the groups a user belongs to" >
		<cfargument name="userDn" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.userPw = arguments.ldapAuthPw;
			lProps.server = variables.ldapServerP;
			//set local prop filter
			lProps.filter = "(&(cn=*)(objectClass=dominoGroup)(member=#arguments.userDn#)))";
			//ldap attributes to get when searching
			lProps.attributes = "member, cn";
			lProps.start = "";
		</cfscript>
		<cfset qValidate = this.queryLdap(lProps) />
		<cfreturn qValidate>
	</cffunction>


	<!---
	get all memebers of a group.  Members can be either groups or users.
	user getGroupUsers to to get only users that are in a group.
	 --->
	<cffunction name="getGroupMemebers" hint="get all memebers of a group, Members can be either groups or users. use getGroupUsers to to get only users that are in a group" access="public" returntype="query">
		<cfargument name="searchFor" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.userPw = arguments.ldapAuthPw;
			lProps.server = variables.ldapServerP;
			//set local prop filter
			lProps.filter = "(CN=#arguments.searchFor#)";
			//ldap attributes to get when searching
			lProps.attributes = "member, cn";
			lProps.start = "";
		</cfscript>
			<cfset qValidate = this.queryLdap(lProps) />
		<cfreturn qValidate>
	</cffunction>
	<!---
	get all users of a group.  Will return a query of only users in a group.
	if the recusre switch is true then when a group is found as a memeber is will
	find all users for the sub group as well.
	 --->
	<cffunction name="getGroupUsers" hint="get all users of a group.  Will return a query of only users in a group, recusre when a group is found as a memeber and will find all users for the sub group as well" access="public" returntype="query">
		<cfargument name="searchFor" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var qMembers = "";
			var curMember = "";
			var qCurMember = "";
			var tmpMem = "";
			var lProps = structCopy(variables.ldapProps);
			var rtnQuery = "";
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			lProps.userPw = arguments.ldapAuthPw;
			lProps.server = variables.ldapServerP;
		</cfscript>
		<!--- get the group members --->
		<cfset qMembers = getGroupMemebers(arguments.searchFor, arguments.ldapAuthId, arguments.ldapAuthPw) />
			<!--- member is a comma delimented list of CN=UID from ldap --->
			<cfloop list="#qMembers.member#" delimiters="," index="curMember">
				<!--- ensure that the current member has a CN= on it for the getMemberUid function --->
				<cfif (FindNoCase('CN=', curMember) NEQ 0)>
					<!--- query ldap for information about the current member to determine if it is a group or person --->
					<!--- drop cn cause getMemberUid is public and public don't know bout cn --->
					<cfset qCurMember = getMemberUid(trim(curMember), arguments.ldapAuthId, arguments.ldapAuthPw) />
					<!--- check is a person or group --->
					<cfif (ucase(qCurMember.objectclass) EQ ucase('top, groupOfNames, dominoGroup'))>
						<!--- recursive call to get sub group users --->
						<cfset tmpMem = getGroupUsers(replace(trim(curMember),"CN=", ""), arguments.ldapAuthId, arguments.ldapAuthPw) />
						<!--- use query of query to join the recursive results and the current results --->
						<cfif isQuery(rtnQuery) and rtnQuery.recordCount NEQ 0 >
							<cfquery name="rtnQuery" dbtype="query">
								SELECT  #variables.ldapProps.attributes#  FROM tmpMem
								UNION
								SELECT  #variables.ldapProps.attributes#  FROM rtnQuery
							</cfquery>
						<cfelse>
							<cfset rtnQuery = tmpMem />
						</cfif>
					<cfelse>
						<!--- use query of query to join the newly found user and the current results --->
						<cfif isQuery(rtnQuery) >
							<cfquery name="rtnQuery" dbtype="query">
								SELECT #variables.ldapProps.attributes# FROM qCurMember
								UNION
								SELECT #variables.ldapProps.attributes# FROM rtnQuery
							</cfquery>
						<cfelse>
							<cfset rtnQuery = qCurMember />
						</cfif>
					</cfif>
				</cfif>
			</cfloop>
		<cfif NOT isQuery(rtnQuery) >
			<!--- this is incase the group name was invalid ensurse you will get a query back.
			have to do this way due to the way cf QoQ select union works --->
			<cfset rtnQuery = queryNew(variables.ldapProps.attributes) />
		</cfif>
		<cfreturn rtnQuery />
	</cffunction>

	<cffunction name="getMemberUid" access="public" returntype="query">
		<cfargument name="searchFor" displayname="string fUid" hint="user id to search LDAP for" type="string" required="yes" />
		<cfargument name="ldapAuthId" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userUID#" />
		<cfargument name="ldapAuthPw" displayname="[string ldapAuthId]" hint="the userid to use for ldap authentication" type="string" required="no" default="#variables.ldapProps.userPw#" />
		<cfscript>
			var loginerror = 0;
			var qValidate = "";
			var lProps = structCopy(variables.ldapProps);  //set the local ldap prop stuct to the current global
			var rtnQuery = QueryNew(variables.ldapProps.attributes);
			//ensure that the global props stuct is set to the primary ldap server
			lProps.server = variables.ldapServerP;
			//overwrite global with function specfic
			lProps.userUID = arguments.ldapAuthId;
			lProps.userPw = arguments.ldapAuthPw;
			lProps.filter = arguments.searchFor;
			lProps.attributes = "objectclass," & variables.ldapProps.attributes;//add objectclass to determine if it is a user or group
			lProps.scope = "subtree";
			lProps.start = "";
		</cfscript>
		<cftry>
			<cfreturn this.queryLdap(lProps) />
			<cfcatch type="any">
				<cfthrow type="ldapUtil"
					 message="LDAP query failed"
					 detail="Primary LDAP Server :: #variables.ldapServerP#<br/>
							 Catch Details:<br/>
							 Type :: #cfcatch.type#<br/>
							 Message :: #cfcatch.message#<br/>
							 Detail ::#cfcatch.detail#<br/>
							 ExtendedInfo :: #cfcatch.ExtendedInfo#<br/>
							 " errorcode="ldapUtil1003"/>
			</cfcatch>
		</cftry>
	</cffunction>


	<!--- interal authentication method for reuse --->
	<cffunction name="queryLdap" displayname="query queryLdap(struct qProps)" hint="internal authentication method" access="package" output="false" returntype="query" >
		<cfargument name="qProps" displayname="struct ldapQueryProps" hint="a struct of the valules to use for the ldap query" type="struct" required="yes" />
		<cfset var qValidate = '' />
		<cfoutput>
			<cfdump var="#qProps#" />
		</cfoutput>
		<cfif not(isValidUsername(arguments.qProps.userUID)) or arguments.qProps.userPw is "">
			<cfthrow type="ldapUtil" detail="The user name or password are of an incorect type" extendedinfo="The user name and password can not be empty.  The user name can not contain @ or ." errorcode="ldapUtil1000" message="Invalid user credentials for authentication" />
		</cfif>
			<cfldap action="QUERY"
	        	name="qValidate"
				scope = "#arguments.qProps.scope#"
			  	start="#arguments.qProps.start#"
				filter="#arguments.qProps.filter#"
				attributes= "#arguments.qProps.attributes#"
				server="#arguments.qProps.server#"
				username="#arguments.qProps.userUID#"
				password="#arguments.qProps.userPw#" />
		<cfreturn qValidate />
	</cffunction>

<!--- standard getter/setter methods --->
	<cffunction name='getLdapServerP' displayname='string getLdapServerP()' hint='get the value of the ldapServerP property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapServerP />
	</cffunction>
	<cffunction name='setLdapServerP' displayname='setLdapServerP(string newLdapServerP)' hint='set the value of the ldapServerP property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapServerP' displayname='string newLdapServerP' hint='new value for the ldapServerP property' type='string' required='yes' />
		<cfset variables.ldapServerP = arguments.newLdapServerP />
	</cffunction>

	<cffunction name='getLdapServerS' displayname='string getLdapServerS()' hint='get the value of the ldapServerS property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapServerS />
	</cffunction>
	<cffunction name='setLdapServerS' displayname='setLdapServerS(string newLdapServerS)' hint='set the value of the ldapServerS property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapServerS' displayname='string newLdapServerS' hint='new value for the ldapServerS property' type='string' required='yes' />
		<cfset variables.ldapServerS = arguments.newLdapServerS />
	</cffunction>

	<cffunction name='getLdapServerT' displayname='string getLdapServerT()' hint='get the value of the ldapServerT property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapServerT />
	</cffunction>
	<cffunction name='setLdapServerT' displayname='setLdapServerT(string newLdapServerT)' hint='set the value of the ldapServerT property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapServerT' displayname='string newLdapServerT' hint='new value for the ldapServerT property' type='string' required='yes' />
		<cfset variables.ldapServerT = arguments.newLdapServerT />
	</cffunction>

	<cffunction name='getLdapScope' displayname='string getLdapScope()' hint='get the value of the ldapScope property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapProps.scope />
	</cffunction>
	<cffunction name='setLdapScope' displayname='setLdapScope(string newLdapScope)' hint='set the value of the ldapScope property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapScope' displayname='string newLdapScope' hint='new value for the ldapScope property' type='string' required='yes' />
		<cfset variables.ldapProps.scope = arguments.newLdapScope />
	</cffunction>

	<cffunction name='getLdapStart' displayname='string getLdapStart()' hint='get the value of the ldapStart property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapProps.start />
	</cffunction>
	<cffunction name='setLdapStart' displayname='setLdapStart(string newLdapStart)' hint='set the value of the ldapStart property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapStart' displayname='string newLdapStart' hint='new value for the ldapStart property' type='string' required='yes' />
		<cfset variables.ldapProps.start = arguments.newLdapStart />
	</cffunction>

	<cffunction name='getLdapAttributes' displayname='string getLdapAttributes()' hint='get the value of the ldapAttributes property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapProps.attributes />
	</cffunction>
	<cffunction name='setLdapAttributes' displayname='setLdapAttributes(string newLdapAttributes)' hint='set the value of the ldapAttributes property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapAttributes' displayname='string newLdapAttributes' hint='new value for the ldapAttributes property' type='string' required='yes' />
		<cfset variables.ldapProps.attributes = arguments.newLdapAttributes />
	</cffunction>

	<cffunction name='getLdapUserUID' displayname='string getLdapUserUID()' hint='get the value of the ldapUserUID property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapProps.userUID />
	</cffunction>
	<cffunction name='setLdapUserUID' displayname='setLdapUserUID(string newLdapUserUID)' hint='set the value of the ldapUserUID property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapUserUID' displayname='string newLdapUserUID' hint='new value for the ldapUserUID property' type='string' required='yes' />
		<cfset variables.ldapProps.userUID = arguments.newLdapUserUID />
	</cffunction>

	<cffunction name='getLdapUserPw' displayname='string getLdapUserPw()' hint='get the value of the ldapUserPw property' access='public' output='false' returntype='string'>
		<cfreturn variables.ldapProps.userPw />
	</cffunction>
	<cffunction name='setLdapUserPw' displayname='setLdapUserPw(string newLdapUserPw)' hint='set the value of the ldapUserPw property' access='public' output='false' returntype='string'>
		<cfargument name='newLdapUserPw' displayname='string newLdapUserPw' hint='new value for the ldapUserPw property' type='string' required='yes' />
		<cfset variables.ldapProps.userPw = arguments.newLdapUserPw />
	</cffunction>

	<cffunction name="getInstance" returntype="struct" access="public">
		<cfreturn variables.ldapProps />
	</cffunction>

</cfcomponent>

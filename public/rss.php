<?php

	require_once('../jsonProcessor.php');
	require_once('../rssBuilder.php');

	if (php_sapi_name() === 'cli') 
	{
		//We're in CLI mode. Supply arguments separated by space, in the form they would be in the URL (such as cvssV3Metrics = LOW, etc)
		parse_str(implode('&', array_slice($argv, 1)), $_GET);
	}

	$theRequestURL = "https://services.nvd.nist.gov/rest/json/cves/2.0?";

	if (isset($_GET['severity'])) 
	{
		$severity = $_GET['severity'];
		$theRequestURL .= "&cvssV3Severity=$severity";
	}

	if (isset($_GET['metric'])) 
	{
		$metric = $_GET['metric'];
		if (!isset($_GET['metric_all'])) 
		{
			$metric = rtrim($metric, '/'); // Delete the last character '/'
		}
		$theRequestURL .= "&cvssV3Metrics=$metric";
	}

	if (isset($_GET['results'])) 
	{
		$results = min($_GET['results'], 50); // At most 50 no matter what
		$theRequestURL .= "&resultsPerPage=$results";
	}

	// Execute the actual call
	$theCURL = curl_init();
	curl_setopt($theCURL, CURLOPT_URL, $theRequestURL);
	curl_setopt($theCURL, CURLOPT_RETURNTRANSFER, 1);
	$theJSONResponse = curl_exec($theCURL);

	if(curl_errno($theCURL)) 
	{
		http_response_code(500);
    	echo "CURL failed: " . curl_error($theCURL);
		return;
	}
	else
	{
		// Processing the response
		curl_close($theCURL);
		
		$theCVEArray = json_decode($theJSONResponse, true)['vulnerabilities'];

		// Actually RSS
		$theParsedVulnerabilities = getVulnerabilities($theCVEArray);
		printRSSBeginning("FMI CVE","https://www.cs.ubbcluj.ro","A customizable feed parsed locally, fetched (with cache) from NIST.","https://www.cs.ubbcluj.ro");
		
		// Print the vunlerabilities in RSS format
		$vulnCount = count($theParsedVulnerabilities);
		for ($i = 0; $i < $vulnCount; $i ++)
		{

			$theTitle_Description = $theParsedVulnerabilities[$i]["description"];
			if(strlen($theTitle_Description) > 64)
			{
				$theTitle_ShortDescription = substr($theTitle_Description, 0, 61) . "...";
			} else 
			{
				$theTitle_ShortDescription = $theTitle_Description;
			}
			$theTitle_MetaID = $theParsedVulnerabilities[$i]["metaID"];
			$theTitle = $theTitle_MetaID . $theParsedVulnerabilities[$i]["baseScore"] . 
										" (".$theParsedVulnerabilities[$i]["baseSeverity"].") - " 
										. $theTitle_ShortDescription;
			$theURL = "https://nvd.nist.gov/vuln/detail/".$theParsedVulnerabilities[$i]["metaID"];
			$theDate = $theParsedVulnerabilities[$i]["lastModified"];
			
			$finalOutput = $theParsedVulnerabilities[$i]["description"] . "<br>";
			$finalOutput .= "Published Date: " . $theParsedVulnerabilities[$i]["publishedDate"] . "<br>";
			$finalOutput .= "Last Modified Date: " . $theParsedVulnerabilities[$i]["lastModified"] . "<br>";
			$finalOutput .= "<br>";
			$finalOutput .= "Attack Vector: " . $theParsedVulnerabilities[$i]["attackVector"] . "<br>";
			$finalOutput .= "Attack Complexity: " . $theParsedVulnerabilities[$i]["attackComplexity"] . "<br>";
			$finalOutput .= "Privileges Required: " . $theParsedVulnerabilities[$i]["privilegesRequired"] . "<br>";
			$finalOutput .= "User Interaction: " . $theParsedVulnerabilities[$i]["userInteraction"] . "<br>";
			$finalOutput .= "Scope: " . $theParsedVulnerabilities[$i]["scope"] . "<br>";
			$finalOutput .= "CIA Impacts: Confidentiality -&gt; " . $theParsedVulnerabilities[$i]["confidentialityImpact"] . ";  Integrity -&gt; " . $theParsedVulnerabilities[$i]["integrityImpact"] . "; Availability -&gt; ". $theParsedVulnerabilities[$i]["availabilityImpact"]. "<br>";
			$finalOutput .= "Severity: Score -&gt; " . $theParsedVulnerabilities[$i]["baseScore"] . "(".$theParsedVulnerabilities[$i]["baseSeverity"].")". "<br>";
			$finalOutput .= "<br>";
			$finalOutput .= "URL: ".$theURL."<br>";
			$finalOutput .= "<br>";

			$finalOutput .= "References: <br>";

			$referenceData = $theParsedVulnerabilities[$i]["references"];
			for ($refIter = 0; $refIter < count($referenceData); $refIter++)
			{
				$url = $referenceData[$refIter]["url"];
				$source = $referenceData[$refIter]["source"];
				$finalOutput .= "$url ($source)<br>";
			}
			printRSSItem($theTitle, $theURL, $finalOutput, "NIST", "", $theDate);
		}

		printRSSEnd();
	}



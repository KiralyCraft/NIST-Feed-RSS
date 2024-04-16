<?php
    function getVulnerabilities($theCVEArray) 
    {
        $vulnerabilities = [];
        $countCVE = count($theCVEArray);

        for ($sequenceCVE = 1; $sequenceCVE <= $countCVE; $sequenceCVE++) {
            $indexCVE = $sequenceCVE - 1;
            $theCVE = $theCVEArray[$indexCVE]['cve'];

            // Fetching CVE metadata
            $theMetaID = $theCVE['id'];
            $theDescription = $theCVE['descriptions'][0]['value'];
            $thePublishedDate = $theCVE['published'];
            $theLastModified = $theCVE['lastModified'];

            // Fetching CVE31 metrics
            $theCVEMetrics = $theCVE['metrics'];
            if (isset($theCVEMetrics) && isset($theCVEMetrics['cvssMetricV31']) && isset($theCVEMetrics['cvssMetricV31'][0]) && isset($theCVEMetrics['cvssMetricV31'][0]['cvssData'])) {
                $theCVE3Metrics = $theCVEMetrics['cvssMetricV31'][0]['cvssData'];

                $vulnerability = [
                    'metaID' => $theMetaID,
                    'description' => $theDescription,
                    'publishedDate' => $thePublishedDate,
                    'lastModified' => $theLastModified,
                    'attackComplexity' => $theCVE3Metrics['attackComplexity'],
                    'attackVector' => $theCVE3Metrics['attackVector'],
                    'availabilityImpact' => $theCVE3Metrics['availabilityImpact'],
                    'baseScore' => $theCVE3Metrics['baseScore'],
                    'baseSeverity' => $theCVE3Metrics['baseSeverity'],
                    'confidentialityImpact' => $theCVE3Metrics['confidentialityImpact'],
                    'integrityImpact' => $theCVE3Metrics['integrityImpact'],
                    'privilegesRequired' => $theCVE3Metrics['privilegesRequired'],
                    'scope' => $theCVE3Metrics['scope'],
                    'userInteraction' => $theCVE3Metrics['userInteraction'],
                    'references' => [],
                ];

                // Fetch the references
                $theReferences = $theCVE['references'];
                $referencesCount = count($theReferences);

                for ($i = 0; $i < $referencesCount; $i++) {
                    $url = $theReferences[$i]['url'];
                    $source = $theReferences[$i]['source'];
                    // Store URL and source in an array
                    $vulnerability['references'][] = ['url' => $url, 'source' => $source];
                }

                $vulnerabilities[] = $vulnerability;
            }
        }

        return $vulnerabilities;
    }

<?php
    function printRSSBeginning($title, $link, $description, $atomLink)
    {
        echo '<?xml version="1.0" encoding="utf-8"?>' . PHP_EOL;
        echo '<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0">' . PHP_EOL;
        echo '<channel>' . PHP_EOL;
        echo '<title>' . htmlspecialchars($title) . '</title>' . PHP_EOL;
        echo '<link>' . htmlspecialchars($link) . '</link>' . PHP_EOL;
        echo '<description>' . htmlspecialchars($description) . '</description>' . PHP_EOL;
        echo '<atom:link href="' . htmlspecialchars($atomLink) . '" rel="self"/>' . PHP_EOL;
        
    }
    function printRSSItem($title, $link, $description, $author, $guid, $pubDate)
    {
        echo '<item>' . PHP_EOL;
        echo '<title>' . htmlspecialchars($title) . '</title>' . PHP_EOL;
        echo '<description>' . htmlspecialchars($description) . '</description>' . PHP_EOL;
        echo '<pubDate>' . date('r', strtotime($pubDate)) . '</pubDate>' . PHP_EOL;
        echo '<link>' . htmlspecialchars($link) . '</link>' . PHP_EOL;
        echo '<author>' . htmlspecialchars($author) . '</author>' . PHP_EOL;
        echo '<guid isPermaLink="false">' . htmlspecialchars($guid) . '</guid>' . PHP_EOL;
        echo '</item>' . PHP_EOL;
    }
    
    function printRSSEnd()
    {
        echo '</channel>' . PHP_EOL;
        echo '</rss>' . PHP_EOL;
    }

<?xml version='1.0' encoding='utf-8'?>

<xsl:stylesheet
	xmlns:xsl='http://www.w3.org/1999/XSL/Transform'
	version='1.0'
	xmlns='http://www.w3.org/1999/xhtml'
	xmlns:http='http://opensource.surakware.com/wiki/apache'
>

	<xsl:output
		method='html'
		encoding='utf-8'
		media-type='text/html'
		doctype-public='-//W3C/DTD XHTML 1.0 Transitional//EN'
	/>

	<xsl:template match='/Hello'>
		<html>
			<head>
				<title>Hello</title>
			</head>
			<body>
				<xsl:apply-templates/>
			</body>
		</html>
	</xsl:template>

	<xsl:template name='DemoForm'>
		<xsl:variable name='message'>
			<xsl:choose>
				<xsl:when test='http:get("message") != ""'>
					<xsl:value-of select='http:get("message")'/>
				</xsl:when>
				<xsl:otherwise>Greetings!</xsl:otherwise>
			</xsl:choose>
		</xsl:variable>

		<div style='border: 1px solid #ccc;'>
			<form method='post'>
				<input type='text' name='message' value='{$message}'/>
				<input type='submit' value='Submit'/>
			</form>

			<xsl:if test='http:get("message") != ""'>
				<hr/>
				Yeah, <xsl:value-of select='$message'/>
			</xsl:if>
		</div>
	</xsl:template>
</xsl:stylesheet>

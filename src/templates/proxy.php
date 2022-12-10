<!DOCTYPE html>
<html>

<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self';"/>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <title> {{title}} </title>
</head>

<body>
    <div class="header">
        <a href="#"><img id="logo-header" src="{{ url_for('static', filename= image_url ) }}"></img></a>
        <a href="#default" id="logo_title" class="logo">{{title_page}}</a>
    </div>
    <div id="content-file">
        <p>{{payload}}</p>
    </div>
</body>
</html>

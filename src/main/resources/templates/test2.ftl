<!DOCTYPE html>
<html>
<head>
    <title>Data Display</title>
    <style>
        .tab {
            display: none;
        }
    </style>
    <script>
        function showTab(event, tabName) {
            var i, tabcontent, tablinks;

            // 隐藏所有的栏目内容
            tabcontent = document.getElementsByClassName("tab");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }

            // 移除栏目选中状态
            tablinks = document.getElementsByClassName("tablink");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }

            // 显示当前选中的栏目内容
            document.getElementById(tabName).style.display = "block";
            event.currentTarget.className += " active";
        }
    </script>
</head>
<body>
<h1>Data Display</h1>

<!-- 栏目标题 -->
<div class="tab">
    <button class="tablink active" onclick="showTab(event, 'vulnerability')">漏洞调用流</button>
    <button class="tablink" onclick="showTab(event, 'method')">方法对应的路径</button>
</div>

<!-- 栏目内容 -->
<div id="vulnerability" class="tab" style="display: block;">
    <!-- 这里放置漏洞调用流数据 -->
    <h2>漏洞调用流数据</h2>
    <p>这是漏洞调用流的内容...</p>
</div>

<div id="method" class="tab">
    <!-- 这里放置方法对应的路径数据 -->
    <h2>方法对应的路径数据</h2>
    <p>这是方法对应的路径的内容...</p>
</div>
</body>
</html>
<!DOCTYPE html>
<html>
<head>
    <title>Data Display</title>
    <meta charset="UTF-8">
    <style>
        .tab {
            display: none;
        }

        .tab-link {
            border: none;
            background-color: transparent;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            color: blue;
            text-decoration: none;
            margin-right: 30px;
        }

        .tab-link.active {
            color: red;
            border-bottom: 2px solid red;
        }
        .container {
            margin: 50px auto;
            width: 800px;
            font-family: Arial, sans-serif;
            color: #333;
        }

        .category {
            margin-bottom: 20px;
        }

        .category h2 {
            margin: 0 0 10px;
            font-size: 24px;
        }

        .category .vulnerability {
            margin-left: 20px;
            padding-left: 20px;
            position: relative;
            border-left: 1px solid #ccc;
        }

        .category .vulnerability:before {
            content: "";
            position: absolute;
            top: 5px;
            left: -11px;
            width: 10px;
            height: 10px;
            background-color: #ccc;
            border-radius: 50%;
            cursor: pointer;
        }

        .category .vulnerability.active:before {
            background-color: #f00;
            transition: all .5s ease-in-out;
        }

        .category .data {
            margin-top: 10px;
            display: none;
        }

        .category .data table {
            width: 100%;
            border-collapse: collapse;
        }

        .category .data th,
        .category .data td {
            padding: 10px;
            border: 1px solid #ccc;
            text-align: center;
        }


    </style>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            var tabLinks = document.querySelectorAll(".tab-link");
            var tabContents = document.querySelectorAll(".tab");

            tabLinks.forEach(function(el) {
                el.addEventListener("click", function() {
                    var current = this;
                    var target = current.dataset.target;

                    // 显示当前选中的栏目内容
                    tabContents.forEach(function(el) {
                        if (el.getAttribute("id") === target) {
                            el.style.display = "block";
                        } else {
                            el.style.display = "none";
                        }
                    });

                    // 移除其他栏目选中状态，给当前选中的栏目添加选中状态
                    tabLinks.forEach(function(el) {
                        if (el === current) {
                            el.classList.add("active");
                        } else {
                            el.classList.remove("active");
                        }
                    });
                });
            });
        });
        var vulnerabilities = document.querySelectorAll('.vulnerability');
        for (var i = 0; i < vulnerabilities.length; i++) {
            vulnerabilities[i].addEventListener('click', function() {
                if (this.classList.contains('active')) {
                    this.classList.remove('active');
                    this.querySelector('.data').style.display = 'none';
                } else {
                    this.classList.add('active');
                    this.querySelector('.data').style.display = 'block';
                }
            });
        }
    </script>
</head>
<body>
<h1>Data Display</h1>

<!-- 栏目标题 -->
<div>
    <a href="#" class="tab-link active" data-target="vulnerability">漏洞调用流</a>
    <a href="#" class="tab-link" data-target="method">方法对应的路径</a>
</div>

<!-- 栏目内容 -->
<div id="vulnerability" class="tab" style="display: block;">
    <!-- 这里放置漏洞调用流数据 -->
<#--    <table>-->
<#--        <tbody>-->
<#--        <#if SSRF??>-->
<#--            <#list SSRF as list>-->
<#--                <#list list as result>-->
<#--                    <tr>-->
<#--                        <td>${result.className}</td>-->
<#--                        <td>${result.methodName}</td>-->
<#--                    </tr>-->
<#--                </#list>-->
<#--            </#list>-->
<#--        </#if>-->
<#--        </tbody>-->
<#--    </table>-->
    <div class="container">
        <div class="category">
            <h2>SSRF</h2>
            <div class="vulnerability">
                <span>漏洞点1</span>
                <div class="data">
                    <table>
                        <thead>
                        <tr>
                            <th>编号</th>
                            <th>标题</th>
                            <th>日期</th>
                            <th>状态</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td>1</td>
                            <td>标题1</td>
                            <td>2021-01-01</td>
                            <td>已修复</td>
                        </tr>
                        <tr>
                            <td>2</td>
                            <td>标题2</td>
                            <td>2021-01-02</td>
                            <td>已修复</td>
                        </tr>
                        <tr>
                            <td>3</td>
                            <td>标题3</td>
                            <td>2021-02-01</td>
                            <td>未修复</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="vulnerability">
                <span>漏洞点2</span>
                <div class="data">
                    <table>
                        <thead>
                        <tr>
                            <th>编号</th>
                            <th>标题</th>
                            <th>日期</th>
                            <th>状态</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td>1</td>
                            <td>标题1</td>
                            <td>2021-01-01</td>
                            <td>已修复</td>
                        </tr>
                        <tr>
                            <td>2</td>
                            <td>标题2</td>
                            <td>2021-01-02</td>
                            <td>已修复</td>
                        </tr>
                        <tr>
                            <td>3</td>
                            <td>标题3</td>
                            <td>2021-02-01</td>
                            <td>未修复</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

</div>

<div id="method" class="tab">
    <!-- 这里放置方法对应的路径数据 -->
    <h2>方法对应的路径数据</h2>
    <p>这是方法对应的路径的内容...</p>
</div>
</body>
</html>
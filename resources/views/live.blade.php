<!DOCTYPE html>
<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css" integrity="sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb" crossorigin="anonymous">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

<script>
$(document).ready(function(){
    function update(){
        $("#data").load("https://barikoi.tk/v1/autocomplete", function(data){
            //data = data.Total;
            //alert("Total: " + data );
            data = JSON.parse(data)
          $("#data").html("Todays Total:  " + data.Total + '<br> <small>Yesterday:</small> ' + '<small>'+data.Yesterday+'</small> <br><small>Total Duplicate: ' + data.Duplicate+'</small><br><small> Total Addresses: '+data.all+'</small>'+'<br><small> Last Week: '+data.lastWeek+'</small>');
        });
    };
    update();
    setInterval(function(){
    update() // this will run after every 5 seconds
}, 5000);



});
</script>
<style media="screen">
h1{
  font-size: 70px;
}

</style>

</head>
<body>
  <div class="container">
    <br>
      <div class="text-center">
        <h2>Live data count update</h2>
        <br>
        <div class="jumbotron">
          <legend>
            <h1 id="data"></h1>
          </legend>
        </div>

      </div>


  </div>


</body>

</html>

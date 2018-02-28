<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateRefindedPlacesTableTable extends Migration
{

    public function up()
    {
        Schema::create('RefindedPlacesTable', function(Blueprint $table) {
            $table->increments('id');
            // Schema declaration
            // Constraints declaration

        });
    }

    public function down()
    {
        Schema::drop('RefindedPlacesTable');
    }
}

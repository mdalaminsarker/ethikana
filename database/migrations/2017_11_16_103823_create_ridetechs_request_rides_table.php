<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateRidetechsRequestRidesTable extends Migration
{

    public function up()
    {
        Schema::create('ridetechs_request_rides', function(Blueprint $table) {
          $table->increments('id');
          $table->string('start_point')->nullable();
          $table->string('destination')->nullable();
          $table->time('pickup_time_from_home')->nullable();
          $table->time('pickup_time_from_office')->nullable();
          $table->string('day_in_week')->nullable();
          $table->string('contact_number')->nullable();
          $table->string('name')->nullable();
          $table->integer('user_id')->unsigned();
          $table->foreign('user_id')->references('id')->on('users');
          $table->timestamps();
            // Schema declaration
            // Constraints declaration

        });
    }

    public function down()
    {
        Schema::drop('ridetechs_request_rides');
    }
}

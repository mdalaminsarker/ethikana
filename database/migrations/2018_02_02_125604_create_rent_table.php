<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateRentTable extends Migration
{

    public function up()
    {
        Schema::create('Rent', function(Blueprint $table) {
          $table->increments('id');
          $table->integer('user_id')->unsigned();
          $table->integer('bike_id')->unsigned();
          $table->dateTime('requested_time')->nullable();
          $table->dateTime('start_time')->nullable();
          $table->dateTime('end_time')->nullable();
          $table->integer('total_rent')->nullable();
          $table->tinyInteger('rent_type')->default(0); // daily or hourly
          $table->tinyInteger('rent_status')->default(0); // Booked , on Going, ended
          $table->foreign('user_id')->references('id')->on('users');
          $table->foreign('bike_id')->references('id')->on('Bike');
          $table->timestamps();

        });
    }

    public function down()
    {
        Schema::drop('Rent');
    }
}

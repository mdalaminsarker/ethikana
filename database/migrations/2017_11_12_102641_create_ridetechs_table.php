<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateRidetechsTable extends Migration
{

    public function up()
    {
        Schema::create('ridetechs', function(Blueprint $table) {
            $table->increments('id');
            $table->string('start_point')->nullable();
            $table->string('destination')->nullable();
            $table->time('pickup_time')->nullable();
            $table->time('dropoff_time')->nullable();
            $table->string('day_in_week')->nullable();
            $table->integer('fare')->nullable();
            $table->string('car_model')->nullable();
            $table->integer('user_id')->unsigned();
            $table->foreign('user_id')->references('id')->on('users');
            $table->timestamps();

            // Schema declaration
            // Constraints declaration

        });
    }

    public function down()
    {
        Schema::drop('ridetechs');
    }
}

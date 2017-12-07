<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateBookARidesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('book_a_rides', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->integer('offer_rides_id')->unsigned();
            $table->tinyInteger('rideStat')->default(0);
            //requested=0, acceptedByDriver=1,notAcceptedByDriver=2,cancelledByDriver=3, cancelledByRider=4; rideComplete=5;
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');  
            $table->foreign('offer_rides_id')->references('id')->on('offer_rides')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('book_a_rides');
    }
}

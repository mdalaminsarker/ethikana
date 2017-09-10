<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOffersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        //offers by business users
        Schema::create('offers', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('pid')->unsigned();
            $table->text('offer_title');
            $table->text('offer_description');
            $table->tinyInteger('isActive')->default(1);
            $table->foreign('pid')->references('id')->on('places')->onDelete('cascade'); 
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
        Schema::dropIfExists('offers');
    }
}

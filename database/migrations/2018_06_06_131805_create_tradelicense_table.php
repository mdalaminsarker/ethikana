<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateTradelicenseTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
      Schema::create('tradelicense', function(Blueprint $table) {
          $table->increments('id');
          $table->integer('pid')->unsigned();
          $table->string('owner_name')->nullable();
          $table->string('email')->nullable();
          $table->string('business_type')->nullable();
          $table->string('trade_license_number')->nullable();
          $table->integer('trade_license_fee')->nullable();
          $table->integer('signboard_tax')->nullable();
          $table->integer('number_of_signboard')->nullable();
          $table->integer('signboard_size')->nullable();
          $table->date('trade_license_issue_date')->nullable();
          $table->date('trade_license_renewal_date')->nullable();
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
        //
        Schema::dropIfExists('tradelicense');
    }
}
